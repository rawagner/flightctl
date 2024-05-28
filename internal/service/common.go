package service

import (
	"encoding/json"

	jsonpatch "github.com/evanphx/json-patch"
	api "github.com/flightctl/flightctl/api/v1alpha1"
)

func NilOutManagedObjectMetaProperties(om *api.ObjectMeta) {
	om.Generation = nil
	om.Owner = nil
	om.Annotations = nil
	om.CreationTimestamp = nil
	om.DeletionTimestamp = nil
}

func ApplyJSONPatch[T any](obj T, newObj T, patchRequest api.PatchRequest) error {
	patch, err := json.Marshal(patchRequest)
	if err != nil {
		return err
	}
	jsonPatch, err := jsonpatch.DecodePatch(patch)
	if err != nil {
		return err
	}

	objJSON, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	newJSON, err := jsonPatch.Apply(objJSON)
	if err != nil {
		return err
	}

	return json.Unmarshal(newJSON, &newObj)
}
