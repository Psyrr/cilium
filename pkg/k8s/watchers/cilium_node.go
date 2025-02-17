// Copyright 2016-2019 Authors of Cilium
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

package watchers

import (
	"sync"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/serializer"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumNodeInit(ciliumNPClient *k8s.K8sCiliumClient, serNodes *serializer.FunctionQueue, asyncControllers *sync.WaitGroup) {

	// CiliumNode objects are used for node discovery until the key-value
	// store is connected
	var once sync.Once
	for {
		swgNodes := lock.NewStoppableWaitGroup()
		_, ciliumNodeInformer := informer.NewInformer(
			cache.NewListWatchFromClient(ciliumNPClient.CiliumV2().RESTClient(),
				"ciliumnodes", v1.NamespaceAll, fields.Everything()),
			&cilium_v2.CiliumNode{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(metricCiliumNode, metricCreate, valid, equal) }()
					if ciliumNode, ok := obj.(*cilium_v2.CiliumNode); ok {
						valid = true
						n := node.ParseCiliumNode(ciliumNode)
						if n.IsLocal() {
							return
						}
						swgNodes.Add()
						serNodes.Enqueue(func() error {
							defer swgNodes.Done()
							k.nodeDiscoverManager.NodeUpdated(n)
							k.K8sEventProcessed(metricCiliumNode, metricCreate, true)
							return nil
						}, serializer.NoRetry)
					}
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(metricCiliumNode, metricUpdate, valid, equal) }()
					if ciliumNode, ok := newObj.(*cilium_v2.CiliumNode); ok {
						valid = true
						n := node.ParseCiliumNode(ciliumNode)
						if n.IsLocal() {
							return
						}
						swgNodes.Add()
						serNodes.Enqueue(func() error {
							defer swgNodes.Done()
							k.nodeDiscoverManager.NodeUpdated(n)
							k.K8sEventProcessed(metricCiliumNode, metricUpdate, true)
							return nil
						}, serializer.NoRetry)
					}
				},
				DeleteFunc: func(obj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(metricCiliumNode, metricDelete, valid, equal) }()
					ciliumNode := k8s.CopyObjToCiliumNode(obj)
					if ciliumNode == nil {
						deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
						if !ok {
							return
						}
						// Delete was not observed by the watcher but is
						// removed from kube-apiserver. This is the last
						// known state and the object no longer exists.
						ciliumNode = k8s.CopyObjToCiliumNode(deletedObj.Obj)
						if ciliumNode == nil {
							return
						}
					}
					valid = true
					n := node.ParseCiliumNode(ciliumNode)
					swgNodes.Add()
					serNodes.Enqueue(func() error {
						defer swgNodes.Done()
						k.nodeDiscoverManager.NodeDeleted(n)
						return nil
					}, serializer.NoRetry)
				},
			},
			k8s.ConvertToCiliumNode,
		)
		isConnected := make(chan struct{})
		// once isConnected is closed, it will stop waiting on caches to be
		// synchronized.
		k.blockWaitGroupToSyncResources(isConnected, swgNodes, ciliumNodeInformer, k8sAPIGroupCiliumNodeV2)

		once.Do(func() {
			// Signalize that we have put node controller in the wait group
			// to sync resources.
			asyncControllers.Done()
		})
		k.k8sAPIGroups.addAPI(k8sAPIGroupCiliumNodeV2)
		go ciliumNodeInformer.Run(isConnected)

		<-kvstore.Client().Connected()
		close(isConnected)

		log.Info("Connected to key-value store, stopping CiliumNode watcher")

		k.k8sAPIGroups.removeAPI(k8sAPIGroupCiliumNodeV2)
		// Create a new node controller when we are disconnected with the
		// kvstore
		<-kvstore.Client().Disconnected()

		log.Info("Disconnected from key-value store, restarting CiliumNode watcher")
	}
}
