package service

import (
	"context"
	"fmt"

	"github.com/flightctl/flightctl/internal/api/server"
	"github.com/flightctl/flightctl/internal/flterrors"
	"github.com/flightctl/flightctl/internal/store"
	"github.com/flightctl/flightctl/internal/util"
	"github.com/go-openapi/swag"
	"k8s.io/apimachinery/pkg/labels"
)

// (POST /api/v1/devices)
func (h *ServiceHandler) CreateDevice(ctx context.Context, request server.CreateDeviceRequestObject) (server.CreateDeviceResponseObject, error) {
	orgId := store.NullOrgId
	if request.Body.Metadata.Name == nil {
		return server.CreateDevice400JSONResponse{Message: "metadata.name not specified"}, nil
	}

	// don't set fields that are managed by the service
	request.Body.Status = nil
	NilOutManagedObjectMetaProperties(&request.Body.Metadata)

	result, err := h.store.Device().Create(ctx, orgId, request.Body, h.taskManager.DeviceUpdatedCallback)
	switch err {
	case nil:
		return server.CreateDevice201JSONResponse(*result), nil
	case flterrors.ErrResourceIsNil:
		return server.CreateDevice400JSONResponse{Message: err.Error()}, nil
	default:
		return nil, err
	}
}

// (GET /api/v1/devices)
func (h *ServiceHandler) ListDevices(ctx context.Context, request server.ListDevicesRequestObject) (server.ListDevicesResponseObject, error) {
	orgId := store.NullOrgId
	labelSelector := ""
	if request.Params.LabelSelector != nil {
		labelSelector = *request.Params.LabelSelector
	}

	labelMap, err := labels.ConvertSelectorToLabelsMap(labelSelector)
	if err != nil {
		return nil, err
	}

	cont, err := store.ParseContinueString(request.Params.Continue)
	if err != nil {
		return server.ListDevices400JSONResponse{Message: fmt.Sprintf("failed to parse continue parameter: %v", err)}, nil
	}

	listParams := store.ListParams{
		Labels:   labelMap,
		Limit:    int(swag.Int32Value(request.Params.Limit)),
		Continue: cont,
		Owner:    request.Params.Owner,
	}
	if listParams.Limit == 0 {
		listParams.Limit = store.MaxRecordsPerListRequest
	}
	if listParams.Limit > store.MaxRecordsPerListRequest {
		return server.ListDevices400JSONResponse{Message: fmt.Sprintf("limit cannot exceed %d", store.MaxRecordsPerListRequest)}, nil
	}

	result, err := h.store.Device().List(ctx, orgId, listParams)
	switch err {
	case nil:
		return server.ListDevices200JSONResponse(*result), nil
	default:
		return nil, err
	}
}

// (DELETE /api/v1/devices)
func (h *ServiceHandler) DeleteDevices(ctx context.Context, request server.DeleteDevicesRequestObject) (server.DeleteDevicesResponseObject, error) {
	orgId := store.NullOrgId

	err := h.store.Device().DeleteAll(ctx, orgId, h.taskManager.AllDevicesDeletedCallback)
	switch err {
	case nil:
		return server.DeleteDevices200JSONResponse{}, nil
	default:
		return nil, err
	}
}

// (GET /api/v1/devices/{name})
func (h *ServiceHandler) ReadDevice(ctx context.Context, request server.ReadDeviceRequestObject) (server.ReadDeviceResponseObject, error) {
	orgId := store.NullOrgId

	result, err := h.store.Device().Get(ctx, orgId, request.Name)
	switch err {
	case nil:
		return server.ReadDevice200JSONResponse(*result), nil
	case flterrors.ErrResourceNotFound:
		return server.ReadDevice404JSONResponse{}, nil
	default:
		return nil, err
	}
}

// (PUT /api/v1/devices/{name})
func (h *ServiceHandler) ReplaceDevice(ctx context.Context, request server.ReplaceDeviceRequestObject) (server.ReplaceDeviceResponseObject, error) {
	orgId := store.NullOrgId
	if request.Body.Metadata.Name == nil {
		return server.ReplaceDevice400JSONResponse{Message: "metadata.name not specified"}, nil
	}
	if request.Name != *request.Body.Metadata.Name {
		return server.ReplaceDevice400JSONResponse{Message: "resource name specified in metadata does not match name in path"}, nil
	}

	// don't overwrite fields that are managed by the service
	request.Body.Status = nil
	NilOutManagedObjectMetaProperties(&request.Body.Metadata)

	result, created, err := h.store.Device().CreateOrUpdate(ctx, orgId, request.Body, nil, true, h.taskManager.DeviceUpdatedCallback)
	switch err {
	case nil:
		if created {
			return server.ReplaceDevice201JSONResponse(*result), nil
		} else {
			return server.ReplaceDevice200JSONResponse(*result), nil
		}
	case flterrors.ErrResourceIsNil:
		return server.ReplaceDevice400JSONResponse{Message: err.Error()}, nil
	case flterrors.ErrResourceNameIsNil:
		return server.ReplaceDevice400JSONResponse{Message: err.Error()}, nil
	case flterrors.ErrResourceNotFound:
		return server.ReplaceDevice404JSONResponse{}, nil
	case flterrors.ErrUpdatingResourceWithOwnerNotAllowed:
		return server.ReplaceDevice409JSONResponse{Message: err.Error()}, nil
	default:
		return nil, err
	}
}

// (DELETE /api/v1/devices/{name})
func (h *ServiceHandler) DeleteDevice(ctx context.Context, request server.DeleteDeviceRequestObject) (server.DeleteDeviceResponseObject, error) {
	orgId := store.NullOrgId

	err := h.store.Device().Delete(ctx, orgId, request.Name, h.taskManager.DeviceUpdatedCallback)
	switch err {
	case nil:
		return server.DeleteDevice200JSONResponse{}, nil
	case flterrors.ErrResourceNotFound:
		return server.DeleteDevice404JSONResponse{}, nil
	default:
		return nil, err
	}
}

// (GET /api/v1/devices/{name}/status)
func (h *ServiceHandler) ReadDeviceStatus(ctx context.Context, request server.ReadDeviceStatusRequestObject) (server.ReadDeviceStatusResponseObject, error) {
	orgId := store.NullOrgId

	result, err := h.store.Device().Get(ctx, orgId, request.Name)
	switch err {
	case nil:
		return server.ReadDeviceStatus200JSONResponse(*result), nil
	case flterrors.ErrResourceNotFound:
		return server.ReadDeviceStatus404JSONResponse{}, nil
	default:
		return nil, err
	}
}

// (PUT /api/v1/devices/{name}/status)
func (h *ServiceHandler) ReplaceDeviceStatus(ctx context.Context, request server.ReplaceDeviceStatusRequestObject) (server.ReplaceDeviceStatusResponseObject, error) {
	orgId := store.NullOrgId

	device := request.Body
	device.Status.UpdatedAt = util.TimeStampStringPtr()

	result, err := h.store.Device().UpdateStatus(ctx, orgId, device)
	switch err {
	case nil:
		return server.ReplaceDeviceStatus200JSONResponse(*result), nil
	case flterrors.ErrResourceIsNil:
		return server.ReplaceDeviceStatus400JSONResponse{Message: err.Error()}, nil
	case flterrors.ErrResourceNameIsNil:
		return server.ReplaceDeviceStatus400JSONResponse{Message: err.Error()}, nil
	case flterrors.ErrResourceNotFound:
		return server.ReplaceDeviceStatus404JSONResponse{}, nil
	default:
		return nil, err
	}
}

// (GET /api/v1/devices/{name}/rendered)
func (h *ServiceHandler) GetRenderedDeviceSpec(ctx context.Context, request server.GetRenderedDeviceSpecRequestObject) (server.GetRenderedDeviceSpecResponseObject, error) {
	orgId := store.NullOrgId

	result, err := h.store.Device().GetRendered(ctx, orgId, request.Name, request.Params.KnownOwner, request.Params.KnownTemplateVersion)
	switch err {
	case nil:
		if result == nil {
			return server.GetRenderedDeviceSpec204Response{}, nil
		}
		return server.GetRenderedDeviceSpec200JSONResponse(*result), nil
	case flterrors.ErrResourceNotFound:
		return server.GetRenderedDeviceSpec404JSONResponse{}, nil
	case flterrors.ErrResourceOwnerIsNil:
		return server.GetRenderedDeviceSpec409JSONResponse{Message: err.Error()}, nil
	case flterrors.ErrTemplateVersionIsNil:
		return server.GetRenderedDeviceSpec409JSONResponse{Message: err.Error()}, nil
	case flterrors.ErrInvalidTemplateVersion:
		return server.GetRenderedDeviceSpec409JSONResponse{Message: err.Error()}, nil
	default:
		return nil, err
	}
}
