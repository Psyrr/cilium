// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/types"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// CNPStatusEventHandler handles status updates events for all CNPs in the
// cluster. Upon creation of CNPs, it will start a controller for that CNP which
// handles sending of updates for that CNP to the Kubernetes API server. Upon
// receiving events from the key-value store, it will send the update for the
// CNP corresponding to the status update to the controller for that CNP.
type CNPStatusEventHandler struct {
	eventMap       *cnpEventMap
	controllers    *controller.Manager
	cnpStore       *store.SharedStore
	k8sStore       cache.Store
	updateInterval time.Duration
}

type cnpEventMap struct {
	lock.RWMutex
	eventMap map[string]chan *NodeStatusUpdate
}

func newCNPEventMap() *cnpEventMap {
	return &cnpEventMap{
		eventMap: make(map[string]chan *NodeStatusUpdate),
	}
}

func (c *cnpEventMap) lookup(cnpKey string) (chan *NodeStatusUpdate, bool) {
	c.RLock()
	ch, ok := c.eventMap[cnpKey]
	c.RUnlock()
	return ch, ok
}

func (c *cnpEventMap) createIfNotExist(cnpKey string) (chan *NodeStatusUpdate, bool) {
	c.Lock()
	ch, ok := c.eventMap[cnpKey]
	// Cannot reinsert into map when active channel present.
	if ok {
		c.Unlock()
		return ch, ok
	}
	ch = make(chan *NodeStatusUpdate, 512)
	c.eventMap[cnpKey] = ch
	c.Unlock()
	return ch, ok
}

func (c *cnpEventMap) delete(cnpKey string) {
	c.Lock()
	delete(c.eventMap, cnpKey)
	c.Unlock()
}

// NewCNPStatusEventHandler returns a new CNPStatusEventHandler.
func NewCNPStatusEventHandler(cnpStore *store.SharedStore, k8sStore cache.Store, updateInterval time.Duration) *CNPStatusEventHandler {
	return &CNPStatusEventHandler{
		eventMap:       newCNPEventMap(),
		controllers:    controller.NewManager(),
		cnpStore:       cnpStore,
		k8sStore:       k8sStore,
		updateInterval: updateInterval,
	}
}

// NodeStatusUpdate pairs a CiliumNetworkPolicyNodeStatus to a specific node.
type NodeStatusUpdate struct {
	node string
	*cilium_v2.CiliumNetworkPolicyNodeStatus
}

// WatchForCNPStatusEvents starts a watcher for all CNP status updates from
// the key-value store.
func (c *CNPStatusEventHandler) WatchForCNPStatusEvents() {

restart:
	watcher := kvstore.Client().ListAndWatch("cnpStatusWatcher", CNPStatusesPath, 512)
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				log.Debugf("%s closed, restarting watch", watcher.String())
				time.Sleep(500 * time.Millisecond)
				goto restart
			}

			switch event.Typ {
			case kvstore.EventTypeListDone, kvstore.EventTypeDelete:
			case kvstore.EventTypeCreate, kvstore.EventTypeModify:
				var cnpStatusUpdate CNPNSWithMeta
				err := json.Unmarshal(event.Value, &cnpStatusUpdate)
				if err != nil {
					log.WithFields(logrus.Fields{"kvstore-event": event.Typ.String(), "key": event.Key}).
						WithError(err).Error("Not updating CNP Status; error unmarshaling data from key-value store")
					continue
				}

				log.WithFields(logrus.Fields{
					"uid":       cnpStatusUpdate.UID,
					"name":      cnpStatusUpdate.Name,
					"namespace": cnpStatusUpdate.Namespace,
					"node":      cnpStatusUpdate.Node,
					"key":       event.Key,
					"type":      event.Typ,
				}).Debug("received event from kvstore")

				// Send the update to the corresponding controller for the
				// CNP which sends all status updates to the K8s apiserver.
				cnpKey := fmt.Sprintf("%s/%s/%s", cnpStatusUpdate.UID, cnpStatusUpdate.Namespace, cnpStatusUpdate.Name)
				ch, ok := c.eventMap.lookup(cnpKey)
				if !ok {
					log.WithField("cnp", cnpKey).Debug("received event from kvstore for cnp for which we do not have any updater goroutine")
				}
				nsu := &NodeStatusUpdate{node: cnpStatusUpdate.Node}
				nsu.CiliumNetworkPolicyNodeStatus = &(cnpStatusUpdate.CiliumNetworkPolicyNodeStatus)

				// TODO - the channel may block once full, which means that
				// we would potentially block for up to 10 seconds (run of the
				// controller) before consuming the next event.
				ch <- nsu
			}
		}
	}
}

// StopController stops the controller which is managing the sending of
// status updates to the Kubernetes APIServer for the given CNP.
func (c *CNPStatusEventHandler) StopController(cnp *types.SlimCNP) {
	cnpKey := getKeyFromObjectMeta(cnp.ObjectMeta)
	prefix := path.Join(CNPStatusesPath, cnpKey)
	err := kvstore.DeletePrefix(prefix)
	if err != nil {
		log.WithError(err).WithField("prefix", prefix).Warning("error deleting prefix from kvstore")
	}
	err = c.controllers.RemoveController(cnpKey)
	if err != nil {
		log.WithError(err).WithField(logfields.Controller, cnpKey).Warning("error removing controller")
	}
}

// StartController starts the controller which sends status updates for the
// given CNP to the Kubernetes APIserver.
func (c *CNPStatusEventHandler) StartController(cnp *types.SlimCNP) {
	cnpKey := path.Join(string(cnp.UID), cnp.Namespace, cnp.Name)
	ch, ok := c.eventMap.createIfNotExist(cnpKey)
	if ok {
		return
	}

	namespace := cnp.Namespace
	name := cnp.Name

	nodeStatusMap := make(map[string]cilium_v2.CiliumNetworkPolicyNodeStatus)
	var hasRun bool
	c.controllers.UpdateController(cnpKey, controller.ControllerParams{
		DoFunc: func(ctx context.Context) error {
			// Get any updates received in case other nodes updated the kvstore
			// before this controller was started, as cilium-agents running in
			// the cluster may receive the CNP event from their own Kubernetes
			// watchers and send keys for their status to the key-value store
			// before this controller has been started.
			if !hasRun {
				sharedKeys := c.cnpStore.SharedKeysMap()
				for k := range sharedKeys {
					// Look for any key which matches this CNP.
					if strings.HasPrefix(k, cnpKey) {
						v, ok := sharedKeys[k].(*CNPNSWithMeta)
						if !ok {
							log.Errorf("received unexpected type mapping to key %s in cnp shared store: %T", k, sharedKeys[k])
							continue
						}
						nodeStatusMap[v.Node] = v.CiliumNetworkPolicyNodeStatus
					}
				}
				hasRun = true
			} else {
				// Wait for one status update to occur.
				select {
				case ev, ok := <-ch:
					if ok {
						nodeStatusMap[ev.node] = *ev.CiliumNetworkPolicyNodeStatus
					}
				case <-ctx.Done():
					return nil
				}
			}

		Loop:
			for {
				select {
				case <-ctx.Done():
					// Controller was stopped, we can simply exit.
					return nil
				case ev, ok := <-ch:
					if ok {
						nodeStatusMap[ev.node] = *ev.CiliumNetworkPolicyNodeStatus
					}
				default:
					// Nothing to do, update K8s apiserver with status updates.
					break Loop
				}
			}

			// This will only be the case after the first run has occurred and
			// there are no subsequent status updates since we don't want for
			// at least one event in the first run.
			if len(nodeStatusMap) == 0 {
				return nil
			}

			var (
				cnp *types.SlimCNP
				err error
			)

			switch {
			// Patching doesn't need us to get the CNP from
			// the store because we can perform patches without
			// needing the actual CNP object itself.s
			case k8sversion.Capabilities().Patch:
			default:
				cnp, err = getUpdatedCNPFromStore(c.k8sStore, fmt.Sprintf("%s/%s", namespace, name))
				if err != nil {
					log.WithError(err).Error("error getting updated cnp from store")
					return err
				}
			}

			// Now that we have collected all events for
			// the given CNP, update the status for all nodes
			// which have sent us updates.
			if err = updateStatusesByCapabilities(CiliumClient(), k8sversion.Capabilities(), cnp, namespace, name, nodeStatusMap); err != nil {
				return err
			}
			return nil
		},
		RunInterval: c.updateInterval,
		StopFunc: func(ctx context.Context) error {
			close(ch)
			c.eventMap.delete(cnpKey)
			return nil
		},
	})
}

func getKeyFromObjectMeta(t metaV1.ObjectMeta) string {
	return path.Join(string(t.UID), t.Namespace, t.Name)
}

func getUpdatedCNPFromStore(ciliumStore cache.Store, nameNamespace string) (*types.SlimCNP, error) {
	serverRuleStore, exists, err := ciliumStore.GetByKey(nameNamespace)
	if err != nil {
		return nil, fmt.Errorf("unable to find v2.CiliumNetworkPolicy in local cache: %s", err)
	}
	if !exists {
		return nil, errors.New("v2.CiliumNetworkPolicy does not exist in local cache")
	}

	serverRule, ok := serverRuleStore.(*types.SlimCNP)
	if !ok {
		return nil, errors.New("received object of unknown type from API server, expecting v2.CiliumNetworkPolicy")
	}

	return serverRule, nil
}
