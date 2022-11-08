/*
Copyright © 2022 Merbridge Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ebpfs

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/merbridge/merbridge/config"
)

var (
	meshPodIpsMap    *ebpf.Map
	pairOriginIpsMap *ebpf.Map
)

func InitLoadPinnedMap() error {
	var err error
	meshPodIpsMap, err = ebpf.LoadPinnedMap(config.MeshPodIps, &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("load map error: %v", err)
	}
	pairOriginIpsMap, err = ebpf.LoadPinnedMap(config.PairOriginalDst, &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("load map error: %v", err)
	}
	return nil
}

func GetMeshPodsMap() *ebpf.Map {
	if meshPodIpsMap == nil {
		_ = InitLoadPinnedMap()
	}
	return meshPodIpsMap
}

func GetPairOriginalMap() *ebpf.Map {
	if meshPodIpsMap == nil {
		_ = InitLoadPinnedMap()
	}
	return pairOriginIpsMap
}
