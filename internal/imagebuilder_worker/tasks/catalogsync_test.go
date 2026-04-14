package tasks

import (
	"context"
	"testing"

	corev1alpha1 "github.com/flightctl/flightctl/api/core/v1alpha1"
	"github.com/flightctl/flightctl/api/core/v1beta1"
	api "github.com/flightctl/flightctl/api/imagebuilder/v1alpha1"
	imagebuilderapi "github.com/flightctl/flightctl/internal/imagebuilder_api/service"
	mainstore "github.com/flightctl/flightctl/internal/store"
	"github.com/flightctl/flightctl/pkg/log"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// mockCatalogStore is a mock Catalog store for catalog sync testing
type mockCatalogStore struct {
	items map[string]*corev1alpha1.CatalogItem
}

func newMockCatalogStore() *mockCatalogStore {
	return &mockCatalogStore{
		items: make(map[string]*corev1alpha1.CatalogItem),
	}
}

func (m *mockCatalogStore) key(catalog, name string) string {
	return catalog + "/" + name
}

func (m *mockCatalogStore) InitialMigration(ctx context.Context) error { return nil }
func (m *mockCatalogStore) Create(ctx context.Context, orgId uuid.UUID, catalog *corev1alpha1.Catalog, _ mainstore.EventCallback) (*corev1alpha1.Catalog, error) {
	return catalog, nil
}
func (m *mockCatalogStore) Update(ctx context.Context, orgId uuid.UUID, catalog *corev1alpha1.Catalog, _ mainstore.EventCallback) (*corev1alpha1.Catalog, error) {
	return catalog, nil
}
func (m *mockCatalogStore) CreateOrUpdate(ctx context.Context, orgId uuid.UUID, catalog *corev1alpha1.Catalog, _ bool, _ mainstore.EventCallback) (*corev1alpha1.Catalog, bool, error) {
	return catalog, true, nil
}
func (m *mockCatalogStore) Get(ctx context.Context, orgId uuid.UUID, name string) (*corev1alpha1.Catalog, error) {
	return nil, nil
}
func (m *mockCatalogStore) List(ctx context.Context, orgId uuid.UUID, params mainstore.ListParams) (*corev1alpha1.CatalogList, error) {
	return &corev1alpha1.CatalogList{}, nil
}
func (m *mockCatalogStore) Delete(ctx context.Context, orgId uuid.UUID, name string, _ mainstore.RemoveOwnerCallback, _ mainstore.EventCallback) error {
	return nil
}
func (m *mockCatalogStore) UpdateStatus(ctx context.Context, orgId uuid.UUID, resource *corev1alpha1.Catalog, _ mainstore.EventCallback) (*corev1alpha1.Catalog, error) {
	return resource, nil
}
func (m *mockCatalogStore) Count(ctx context.Context, orgId uuid.UUID, params mainstore.ListParams) (int64, error) {
	return 0, nil
}
func (m *mockCatalogStore) UnsetOwner(ctx context.Context, tx *gorm.DB, orgId uuid.UUID, owner string) error {
	return nil
}
func (m *mockCatalogStore) UnsetItemOwner(ctx context.Context, tx *gorm.DB, orgId uuid.UUID, owner string) error {
	return nil
}
func (m *mockCatalogStore) ListAllItems(ctx context.Context, orgId uuid.UUID, params mainstore.ListParams) (*corev1alpha1.CatalogItemList, error) {
	return &corev1alpha1.CatalogItemList{}, nil
}
func (m *mockCatalogStore) ListItems(ctx context.Context, orgId uuid.UUID, catalogName string, params mainstore.ListParams) (*corev1alpha1.CatalogItemList, error) {
	return &corev1alpha1.CatalogItemList{}, nil
}
func (m *mockCatalogStore) GetItem(ctx context.Context, orgId uuid.UUID, catalogName string, itemName string) (*corev1alpha1.CatalogItem, error) {
	item, ok := m.items[m.key(catalogName, itemName)]
	if !ok {
		return nil, nil
	}
	return item, nil
}
func (m *mockCatalogStore) CreateItem(ctx context.Context, orgId uuid.UUID, catalogName string, item *corev1alpha1.CatalogItem) (*corev1alpha1.CatalogItem, error) {
	m.items[m.key(catalogName, lo.FromPtr(item.Metadata.Name))] = item
	return item, nil
}
func (m *mockCatalogStore) UpdateItem(ctx context.Context, orgId uuid.UUID, catalogName string, item *corev1alpha1.CatalogItem) (*corev1alpha1.CatalogItem, error) {
	m.items[m.key(catalogName, lo.FromPtr(item.Metadata.Name))] = item
	return item, nil
}
func (m *mockCatalogStore) CreateOrUpdateItem(ctx context.Context, orgId uuid.UUID, catalogName string, item *corev1alpha1.CatalogItem) (*corev1alpha1.CatalogItem, bool, error) {
	k := m.key(catalogName, lo.FromPtr(item.Metadata.Name))
	_, exists := m.items[k]
	m.items[k] = item
	return item, !exists, nil
}
func (m *mockCatalogStore) DeleteItem(ctx context.Context, orgId uuid.UUID, catalogName string, itemName string) error {
	delete(m.items, m.key(catalogName, itemName))
	return nil
}

// mockStoreWithCatalog wraps mockStore and overrides Catalog()
type mockStoreWithCatalog struct {
	*mockStore
	catalog *mockCatalogStore
}

func newMockStoreWithCatalog() *mockStoreWithCatalog {
	return &mockStoreWithCatalog{
		mockStore: newMockStore(),
		catalog:   newMockCatalogStore(),
	}
}

func (m *mockStoreWithCatalog) Catalog() mainstore.Catalog {
	return m.catalog
}

// mockImageCatalogExportService for testing catalog sync
type mockImageCatalogExportService struct {
	exports []api.ImageCatalogExport
}

func (m *mockImageCatalogExportService) Create(ctx context.Context, orgId uuid.UUID, export api.ImageCatalogExport) (*api.ImageCatalogExport, v1beta1.Status) {
	return &export, v1beta1.Status{Code: 201}
}
func (m *mockImageCatalogExportService) Get(ctx context.Context, orgId uuid.UUID, name string) (*api.ImageCatalogExport, v1beta1.Status) {
	return nil, v1beta1.Status{Code: 404}
}
func (m *mockImageCatalogExportService) List(ctx context.Context, orgId uuid.UUID, params api.ListImageCatalogExportsParams) (*api.ImageCatalogExportList, v1beta1.Status) {
	return &api.ImageCatalogExportList{Items: m.exports}, v1beta1.Status{Code: 200}
}
func (m *mockImageCatalogExportService) Delete(ctx context.Context, orgId uuid.UUID, name string) (*api.ImageCatalogExport, v1beta1.Status) {
	return nil, v1beta1.Status{Code: 200}
}
func (m *mockImageCatalogExportService) ListByImageDefinition(ctx context.Context, orgId uuid.UUID, imageDefinitionName string) ([]api.ImageCatalogExport, error) {
	return m.exports, nil
}

// mockImageBuilderServiceWithCatalog wraps the mock to add ImageCatalogExport
type mockImageBuilderServiceWithCatalog struct {
	imageBuild        *mockImageBuildService
	imageCatalogExport *mockImageCatalogExportService
}

func (m *mockImageBuilderServiceWithCatalog) ImageBuild() imagebuilderapi.ImageBuildService {
	return m.imageBuild
}
func (m *mockImageBuilderServiceWithCatalog) ImageExport() imagebuilderapi.ImageExportService {
	return nil
}
func (m *mockImageBuilderServiceWithCatalog) ImageDefinition() imagebuilderapi.ImageDefinitionService {
	return nil
}
func (m *mockImageBuilderServiceWithCatalog) ImageCatalogExport() imagebuilderapi.ImageCatalogExportService {
	return m.imageCatalogExport
}

func newCompletedImageBuildWithDef(name, defName, resolvedVersion string) *api.ImageBuild {
	return &api.ImageBuild{
		ApiVersion: api.ImageBuildAPIVersion,
		Kind:       string(api.ResourceKindImageBuild),
		Metadata:   v1beta1.ObjectMeta{Name: lo.ToPtr(name)},
		Spec: api.ImageBuildSpec{
			ImageDefinitionRef: lo.ToPtr(defName),
		},
		Status: &api.ImageBuildStatus{
			ResolvedVersion: lo.ToPtr(resolvedVersion),
			ResolvedDestination: &api.ImageBuildDestination{
				Repository: "output-repo",
				ImageName:  "my-image",
				ImageTag:   resolvedVersion,
			},
			Conditions: &[]api.ImageBuildCondition{
				{
					Type:   api.ImageBuildConditionTypeReady,
					Status: v1beta1.ConditionStatusTrue,
					Reason: string(api.ImageBuildConditionReasonCompleted),
				},
			},
		},
	}
}

func TestSyncCatalogItems_WhenBuildHasNoResolvedVersion_ShouldSkip(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()
	orgId := uuid.New()

	catalogStore := newMockCatalogStore()
	mainStore := &mockStoreWithCatalog{mockStore: newMockStore(), catalog: catalogStore}
	catalogExportSvc := &mockImageCatalogExportService{
		exports: []api.ImageCatalogExport{
			{
				Spec: api.ImageCatalogExportSpec{
					ImageDefinitionRef: "my-def",
					CatalogRef:         "my-catalog",
				},
			},
		},
	}
	svcWrapper := &mockImageBuilderServiceWithCatalog{
		imageBuild:        &mockImageBuildService{},
		imageCatalogExport: catalogExportSvc,
	}

	consumer := &Consumer{
		mainStore:           mainStore,
		imageBuilderService: svcWrapper,
		log:                 log.InitLogs(),
	}

	build := &api.ImageBuild{
		Spec: api.ImageBuildSpec{
			ImageDefinitionRef: lo.ToPtr("my-def"),
		},
		Status: &api.ImageBuildStatus{
			ResolvedVersion: nil,
		},
	}

	err := consumer.syncCatalogItems(ctx, orgId, build, log.InitLogs())
	req.NoError(err)
	req.Empty(catalogStore.items, "no CatalogItem should be upserted when resolvedVersion is nil")
}

func TestSyncCatalogItems_WhenNoExports_ShouldSkip(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()
	orgId := uuid.New()

	catalogStore := newMockCatalogStore()
	mainStore := &mockStoreWithCatalog{mockStore: newMockStore(), catalog: catalogStore}
	catalogExportSvc := &mockImageCatalogExportService{exports: nil}
	svcWrapper := &mockImageBuilderServiceWithCatalog{
		imageBuild:        &mockImageBuildService{},
		imageCatalogExport: catalogExportSvc,
	}

	consumer := &Consumer{
		mainStore:           mainStore,
		imageBuilderService: svcWrapper,
		log:                 log.InitLogs(),
	}

	build := newCompletedImageBuildWithDef("build-1", "my-def", "1.0.0")
	err := consumer.syncCatalogItems(ctx, orgId, build, log.InitLogs())
	req.NoError(err)
	req.Empty(catalogStore.items, "no CatalogItem should be upserted when no exports exist")
}

func TestSyncCatalogItems_WhenExportExists_ShouldUpsertCatalogItem(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()
	orgId := uuid.New()

	catalogStore := newMockCatalogStore()
	mainStore := &mockStoreWithCatalog{mockStore: newMockStore(), catalog: catalogStore}
	displayName := "My Image"
	shortDesc := "A test image"
	catalogExportSvc := &mockImageCatalogExportService{
		exports: []api.ImageCatalogExport{
			{
				Spec: api.ImageCatalogExportSpec{
					ImageDefinitionRef: "my-def",
					CatalogRef:         "test-catalog",
					CatalogItemName:    lo.ToPtr("my-item"),
					DisplayName:        &displayName,
					ShortDescription:   &shortDesc,
				},
			},
		},
	}
	svcWrapper := &mockImageBuilderServiceWithCatalog{
		imageBuild:        &mockImageBuildService{},
		imageCatalogExport: catalogExportSvc,
	}

	consumer := &Consumer{
		mainStore:           mainStore,
		imageBuilderService: svcWrapper,
		log:                 log.InitLogs(),
	}

	build := newCompletedImageBuildWithDef("build-1", "my-def", "1.0.1")
	err := consumer.syncCatalogItems(ctx, orgId, build, log.InitLogs())
	req.NoError(err)

	item := catalogStore.items["test-catalog/my-item"]
	req.NotNil(item, "CatalogItem should have been upserted")
	req.Equal("my-item", lo.FromPtr(item.Metadata.Name))
	req.Len(item.Spec.Versions, 1, "one version should be present")
	req.Equal("1.0.1", item.Spec.Versions[0].Version)
	req.Equal(displayName, lo.FromPtr(item.Spec.DisplayName))
	req.Equal(shortDesc, lo.FromPtr(item.Spec.ShortDescription))
}

func TestSyncCatalogItems_WhenVersionAlreadyExists_ShouldSkipDuplicate(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()
	orgId := uuid.New()

	catalogStore := newMockCatalogStore()
	// Pre-populate with existing version
	existingItem := &corev1alpha1.CatalogItem{
		ApiVersion: "flightctl.io/v1alpha1",
		Kind:       "CatalogItem",
		Metadata:   corev1alpha1.CatalogItemMeta{Catalog: "test-catalog"},
		Spec: corev1alpha1.CatalogItemSpec{
			Type:    corev1alpha1.CatalogItemTypeOS,
			Versions: []corev1alpha1.CatalogItemVersion{{Version: "1.0.1"}},
		},
	}
	existingItem.Metadata.Name = lo.ToPtr("my-item")
	catalogStore.items["test-catalog/my-item"] = existingItem

	mainStore := &mockStoreWithCatalog{mockStore: newMockStore(), catalog: catalogStore}
	catalogExportSvc := &mockImageCatalogExportService{
		exports: []api.ImageCatalogExport{
			{
				Spec: api.ImageCatalogExportSpec{
					ImageDefinitionRef: "my-def",
					CatalogRef:         "test-catalog",
					CatalogItemName:    lo.ToPtr("my-item"),
				},
			},
		},
	}
	svcWrapper := &mockImageBuilderServiceWithCatalog{
		imageBuild:        &mockImageBuildService{},
		imageCatalogExport: catalogExportSvc,
	}

	consumer := &Consumer{
		mainStore:           mainStore,
		imageBuilderService: svcWrapper,
		log:                 log.InitLogs(),
	}

	build := newCompletedImageBuildWithDef("build-1", "my-def", "1.0.1")
	err := consumer.syncCatalogItems(ctx, orgId, build, log.InitLogs())
	req.NoError(err)

	item := catalogStore.items["test-catalog/my-item"]
	req.Len(item.Spec.Versions, 1, "duplicate version should not be added")
}

func TestSyncCatalogItems_WhenAddingNewVersion_ShouldSetReplaces(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()
	orgId := uuid.New()

	catalogStore := newMockCatalogStore()
	existingItem := &corev1alpha1.CatalogItem{
		ApiVersion: "flightctl.io/v1alpha1",
		Kind:       "CatalogItem",
		Metadata:   corev1alpha1.CatalogItemMeta{Catalog: "test-catalog"},
		Spec: corev1alpha1.CatalogItemSpec{
			Type:    corev1alpha1.CatalogItemTypeOS,
			Versions: []corev1alpha1.CatalogItemVersion{{Version: "1.0.0"}},
		},
	}
	existingItem.Metadata.Name = lo.ToPtr("my-item")
	catalogStore.items["test-catalog/my-item"] = existingItem

	mainStore := &mockStoreWithCatalog{mockStore: newMockStore(), catalog: catalogStore}
	catalogExportSvc := &mockImageCatalogExportService{
		exports: []api.ImageCatalogExport{
			{
				Spec: api.ImageCatalogExportSpec{
					ImageDefinitionRef: "my-def",
					CatalogRef:         "test-catalog",
					CatalogItemName:    lo.ToPtr("my-item"),
				},
			},
		},
	}
	svcWrapper := &mockImageBuilderServiceWithCatalog{
		imageBuild:        &mockImageBuildService{},
		imageCatalogExport: catalogExportSvc,
	}

	consumer := &Consumer{
		mainStore:           mainStore,
		imageBuilderService: svcWrapper,
		log:                 log.InitLogs(),
	}

	build := newCompletedImageBuildWithDef("build-1", "my-def", "1.0.1")
	err := consumer.syncCatalogItems(ctx, orgId, build, log.InitLogs())
	req.NoError(err)

	item := catalogStore.items["test-catalog/my-item"]
	req.Len(item.Spec.Versions, 2)
	req.Equal("1.0.0", item.Spec.Versions[0].Version)
	req.Equal("1.0.1", item.Spec.Versions[1].Version)
	req.Equal("1.0.0", lo.FromPtr(item.Spec.Versions[1].Replaces))
}

func TestSyncCatalogItems_WhenCatalogItemNameAbsent_ShouldDefaultToDefinitionName(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()
	orgId := uuid.New()

	catalogStore := newMockCatalogStore()
	mainStore := &mockStoreWithCatalog{mockStore: newMockStore(), catalog: catalogStore}
	catalogExportSvc := &mockImageCatalogExportService{
		exports: []api.ImageCatalogExport{
			{
				Spec: api.ImageCatalogExportSpec{
					ImageDefinitionRef: "my-def",
					CatalogRef:         "test-catalog",
					// CatalogItemName intentionally absent
				},
			},
		},
	}
	svcWrapper := &mockImageBuilderServiceWithCatalog{
		imageBuild:        &mockImageBuildService{},
		imageCatalogExport: catalogExportSvc,
	}

	consumer := &Consumer{
		mainStore:           mainStore,
		imageBuilderService: svcWrapper,
		log:                 log.InitLogs(),
	}

	build := newCompletedImageBuildWithDef("build-1", "my-def", "1.0.0")
	err := consumer.syncCatalogItems(ctx, orgId, build, log.InitLogs())
	req.NoError(err)

	// Item should be stored under the definition name
	item := catalogStore.items["test-catalog/my-def"]
	req.NotNil(item, "item should default to ImageDefinition name when CatalogItemName is absent")
	req.Equal("my-def", lo.FromPtr(item.Metadata.Name))
}
