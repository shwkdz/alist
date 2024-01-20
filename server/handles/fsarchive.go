package handles

import (
	"context"
	"fmt"
	"io"
	stdfs "io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/alist-org/alist/v3/internal/conf"
	"github.com/alist-org/alist/v3/internal/errs"
	"github.com/alist-org/alist/v3/internal/fs"
	"github.com/alist-org/alist/v3/internal/model"
	"github.com/alist-org/alist/v3/internal/op"
	"github.com/alist-org/alist/v3/internal/setting"
	"github.com/alist-org/alist/v3/internal/sign"
	"github.com/alist-org/alist/v3/pkg/utils"
	"github.com/alist-org/alist/v3/server/common"
	"github.com/avvmoto/buf-readerat"
	"github.com/gin-gonic/gin"
	"github.com/mholt/archiver/v4"
	"github.com/pkg/errors"
	"github.com/snabb/httpreaderat"
)

type FsArchiveListReq struct {
	ListReq
	SubPath string `json:"sub_path" form:"sub_path"`
}

type FsArchiveListResp struct {
	FsListResp
}

func FsArchiveList(c *gin.Context) {
	var req FsArchiveListReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	user := c.MustGet("user").(*model.User)
	reqPath, err := user.JoinPath(req.Path)
	if err != nil {
		common.ErrorResp(c, err, 403)
		return
	}
	meta, err := op.GetNearestMeta(reqPath)
	if err != nil {
		if !errors.Is(errors.Cause(err), errs.MetaNotFound) {
			common.ErrorResp(c, err, 500)
			return
		}
	}
	c.Set("meta", meta)
	if !common.CanAccess(user, meta, reqPath, req.Password) {
		common.ErrorStrResp(c, "password is incorrect or you have no permission", 403)
		return
	}
	obj, err := fs.Get(c, reqPath, &fs.GetArgs{})
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	var rawURL string

	storage, err := fs.GetStorage(reqPath, &fs.GetStoragesArgs{})
	provider := "unknown"
	if err == nil {
		provider = storage.Config().Name
	}
	if obj.IsDir() {
		err := errs.NotSupport
		common.ErrorResp(c, err, 400)
		return
	}
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	if storage.Config().MustProxy() || storage.GetStorage().WebProxy {
		query := ""
		if isEncrypt(meta, reqPath) || setting.GetBool(conf.SignAll) {
			query = "?sign=" + sign.Sign(reqPath)
		}
		if storage.GetStorage().DownProxyUrl != "" {
			rawURL = fmt.Sprintf("%s%s?sign=%s",
				strings.Split(storage.GetStorage().DownProxyUrl, "\n")[0],
				utils.EncodePath(reqPath, true),
				sign.Sign(reqPath))
		} else {
			rawURL = fmt.Sprintf("%s/p%s%s",
				common.GetApiUrl(c.Request),
				utils.EncodePath(reqPath, true),
				query)
		}
	} else {
		// file have raw url
		if url, ok := model.GetUrl(obj); ok {
			rawURL = url
		} else {
			// if storage is not proxy, use raw url by fs.Link
			link, _, err := fs.Link(c, reqPath, model.LinkArgs{
				IP:      c.ClientIP(),
				Header:  c.Request.Header,
				HttpReq: c.Request,
			})
			if err != nil {
				common.ErrorResp(c, err, 500)
				return
			}
			rawURL = link.URL
		}
	}

	// 新增解压部分
	reqSubPath, err := user.JoinPath(req.SubPath)
	if err != nil {
		common.ErrorResp(c, err, 403)
		return
	}
	if reqSubPath != "/" {
		reqSubPath = reqSubPath + "/"
	}

	httpReaderAtReq, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	httpReaderAtReq.Header.Set("Cookie", c.GetHeader("Cookie"))
	httpReaderAtReq.Header.Set("User-Agent", c.GetHeader("User-Agent"))
	htrdr, err := httpreaderat.New(nil, httpReaderAtReq, nil)
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	bhtrdr := bufra.NewBufReaderAt(htrdr, 1024*1024)
	arc, err := DetectArchive(reqPath, io.NewSectionReader(bhtrdr, 0, htrdr.Size()))
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}

	dFiles, err := arc.ExtractDirs(c, reqSubPath)
	if err != nil {
		common.ErrorResp(c, errs.NotSupport, 500)
		return
	}

	objs := make([]model.Obj, 0, len(dFiles))
	for _, f := range dFiles {
		objs = append(objs, &ArchiveFileObj{fs: f.FileInfo, nameInArchive: f.NameInArchive})
	}
	total, objs := pagination(objs, &req.PageReq)

	flr := FsListResp{
		Content:  toObjsResp(objs, reqPath, isEncrypt(meta, reqPath)),
		Total:    int64(total),
		Readme:   getReadme(meta, reqPath),
		Header:   getHeader(meta, reqPath),
		Write:    user.CanWrite() || common.CanWrite(meta, reqPath),
		Provider: provider,
	}
	common.SuccessResp(c, FsArchiveListResp{
		FsListResp: flr,
	})
}

type FsArchiveGetReq struct {
	FsGetReq
	SubPath string `json:"sub_path" form:"sub_path"`
}
type FsArchiveGetResp struct {
	FsGetResp
}

func FsArchiveGet(c *gin.Context) {
	var req FsArchiveGetReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	user := c.MustGet("user").(*model.User)
	reqPath, err := user.JoinPath(req.Path)
	if err != nil {
		common.ErrorResp(c, err, 403)
		return
	}
	meta, err := op.GetNearestMeta(reqPath)
	if err != nil {
		if !errors.Is(errors.Cause(err), errs.MetaNotFound) {
			common.ErrorResp(c, err, 500)
			return
		}
	}
	c.Set("meta", meta)
	if !common.CanAccess(user, meta, reqPath, req.Password) {
		common.ErrorStrResp(c, "password is incorrect or you have no permission", 403)
		return
	}
	obj, err := fs.Get(c, reqPath, &fs.GetArgs{})
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	var rawURL string

	storage, err := fs.GetStorage(reqPath, &fs.GetStoragesArgs{})
	provider := "unknown"
	if err == nil {
		provider = storage.Config().Name
	}
	if obj.IsDir() {
		err := errs.NotSupport
		common.ErrorResp(c, err, 400)
		return
	}
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	if storage.Config().MustProxy() || storage.GetStorage().WebProxy {
		query := ""
		if isEncrypt(meta, reqPath) || setting.GetBool(conf.SignAll) {
			query = "?sign=" + sign.Sign(reqPath)
		}
		if storage.GetStorage().DownProxyUrl != "" {
			rawURL = fmt.Sprintf("%s%s?sign=%s",
				strings.Split(storage.GetStorage().DownProxyUrl, "\n")[0],
				utils.EncodePath(reqPath, true),
				sign.Sign(reqPath))
		} else {
			rawURL = fmt.Sprintf("%s/p%s%s",
				common.GetApiUrl(c.Request),
				utils.EncodePath(reqPath, true),
				query)
		}
	} else {
		// file have raw url
		if url, ok := model.GetUrl(obj); ok {
			rawURL = url
		} else {
			// if storage is not proxy, use raw url by fs.Link
			link, _, err := fs.Link(c, reqPath, model.LinkArgs{
				IP:      c.ClientIP(),
				Header:  c.Request.Header,
				HttpReq: c.Request,
			})
			if err != nil {
				common.ErrorResp(c, err, 500)
				return
			}
			rawURL = link.URL
		}
	}
	// var related []model.Obj
	parentPath := path.Dir(reqPath)
	// sameLevelFiles, err := fs.List(c, parentPath, &fs.ListArgs{})
	// if err == nil {
	// related = filterRelated(sameLevelFiles, obj)
	// }
	// parentMeta, _ := op.GetNearestMeta(parentPath)
	thumb, _ := model.GetThumb(obj)

	// 新增解压部分
	reqSubPath, err := user.JoinPath(req.SubPath)
	newRawURL := fmt.Sprintf("%s/api/fs/archive_proxy?path=%s&sub_path=%s",
		common.GetApiUrl(c.Request),
		utils.EncodePath(reqPath, true),
		utils.EncodePath(reqSubPath, true))
	if err != nil {
		common.ErrorResp(c, err, 403)
		return
	}

	httpReaderAtReq, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	httpReaderAtReq.Header.Set("Cookie", c.GetHeader("Cookie"))
	httpReaderAtReq.Header.Set("User-Agent", c.GetHeader("User-Agent"))
	htrdr, err := httpreaderat.New(nil, httpReaderAtReq, nil)
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	bhtrdr := bufra.NewBufReaderAt(htrdr, 1024*1024)
	arc, err := DetectArchive(reqPath, io.NewSectionReader(bhtrdr, 0, htrdr.Size()))
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}

	dFile, err := arc.ExtractFile(c, reqSubPath)
	if err != nil {
		common.ErrorResp(c, errs.ObjectNotFound, 500)
		return
	}

	obj = &ArchiveFileObj{fs: dFile.FileInfo, nameInArchive: dFile.NameInArchive}
	fgr := FsGetResp{
		ObjResp: ObjResp{
			Name:        obj.GetName(),
			Size:        obj.GetSize(),
			IsDir:       obj.IsDir(),
			Modified:    obj.ModTime(),
			Created:     obj.CreateTime(),
			HashInfoStr: obj.GetHash().String(),
			HashInfo:    obj.GetHash().Export(),
			Sign:        common.Sign(obj, parentPath, isEncrypt(meta, reqPath)),
			Type:        utils.GetFileType(obj.GetName()),
			Thumb:       thumb,
		},
		RawURL:   newRawURL,
		Readme:   getReadme(meta, reqPath),
		Header:   getHeader(meta, reqPath),
		Provider: provider,
		// Related:  toObjsResp(related, parentPath, isEncrypt(parentMeta, parentPath)),
	}

	common.SuccessResp(c, FsArchiveGetResp{
		FsGetResp: fgr,
	})
}

type FsArchiveProxyReq struct {
	Path     string `json:"path" form:"path"`
	Password string `json:"password" form:"password"`
	SubPath  string `json:"sub_path" form:"sub_path"`
}

func FsArchiveProxy(c *gin.Context) {
	var req FsArchiveProxyReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	user := c.MustGet("user").(*model.User)
	reqPath, err := user.JoinPath(req.Path)
	if err != nil {
		common.ErrorResp(c, err, 403)
		return
	}
	meta, err := op.GetNearestMeta(reqPath)
	if err != nil {
		if !errors.Is(errors.Cause(err), errs.MetaNotFound) {
			common.ErrorResp(c, err, 500)
			return
		}
	}
	c.Set("meta", meta)
	if !common.CanAccess(user, meta, reqPath, req.Password) {
		common.ErrorStrResp(c, "password is incorrect or you have no permission", 403)
		return
	}
	obj, err := fs.Get(c, reqPath, &fs.GetArgs{})
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	var rawURL string

	storage, err := fs.GetStorage(reqPath, &fs.GetStoragesArgs{})
	if obj.IsDir() {
		err := errs.NotSupport
		common.ErrorResp(c, err, 400)
		return
	}
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	if storage.Config().MustProxy() || storage.GetStorage().WebProxy {
		query := ""
		if isEncrypt(meta, reqPath) || setting.GetBool(conf.SignAll) {
			query = "?sign=" + sign.Sign(reqPath)
		}
		if storage.GetStorage().DownProxyUrl != "" {
			rawURL = fmt.Sprintf("%s%s?sign=%s",
				strings.Split(storage.GetStorage().DownProxyUrl, "\n")[0],
				utils.EncodePath(reqPath, true),
				sign.Sign(reqPath))
		} else {
			rawURL = fmt.Sprintf("%s/p%s%s",
				common.GetApiUrl(c.Request),
				utils.EncodePath(reqPath, true),
				query)
		}
	} else {
		// file have raw url
		if url, ok := model.GetUrl(obj); ok {
			rawURL = url
		} else {
			// if storage is not proxy, use raw url by fs.Link
			link, _, err := fs.Link(c, reqPath, model.LinkArgs{
				IP:      c.ClientIP(),
				Header:  c.Request.Header,
				HttpReq: c.Request,
			})
			if err != nil {
				common.ErrorResp(c, err, 500)
				return
			}
			rawURL = link.URL
		}
	}

	// 新增解压部分
	reqSubPath, err := user.JoinPath(req.SubPath)
	if err != nil {
		common.ErrorResp(c, err, 403)
		return
	}

	httpReaderAtReq, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	httpReaderAtReq.Header.Set("Cookie", c.GetHeader("Cookie"))
	httpReaderAtReq.Header.Set("User-Agent", c.GetHeader("User-Agent"))
	htrdr, err := httpreaderat.New(nil, httpReaderAtReq, nil)
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	bhtrdr := bufra.NewBufReaderAt(htrdr, 1024*1024)
	arc, err := DetectArchive(reqPath, io.NewSectionReader(bhtrdr, 0, htrdr.Size()))
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}

	dFile, err := arc.ExtractFile(c, reqSubPath)
	if err != nil {
		common.ErrorResp(c, errs.ObjectNotFound, 500)
		return
	}
	fr, err := dFile.Open()
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	defer fr.Close()
	fileName := dFile.Name()
	c.DataFromReader(http.StatusOK, dFile.Size(), "application/octet-stream", fr, map[string]string{
		"Content-Disposition": fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, fileName, url.PathEscape(fileName)),
		"Content-Type":        utils.GetMimeType(fileName),
	})
}

type ArchiveFileObj struct {
	fs            os.FileInfo
	nameInArchive string
}

func (f *ArchiveFileObj) GetFullPath() string {
	return f.nameInArchive
}

func (f *ArchiveFileObj) GetSize() int64 {
	return f.fs.Size()
}

func (f *ArchiveFileObj) GetName() string {
	return f.fs.Name()
}

func (f *ArchiveFileObj) ModTime() time.Time {
	return f.fs.ModTime()
}

func (f *ArchiveFileObj) CreateTime() time.Time {
	return f.fs.ModTime()
}

func (f *ArchiveFileObj) IsDir() bool {
	return f.fs.IsDir()
}

func (f *ArchiveFileObj) GetHash() utils.HashInfo {
	return utils.NewHashInfo(utils.SHA1, "")
}

func (f *ArchiveFileObj) GetID() string {
	return "" // todo
}

func (f *ArchiveFileObj) GetPath() string {
	return "" // todo
}

var _ model.Obj = (*ArchiveFileObj)(nil)

func NewZipArchive(sourceArchive io.Reader) *ArchiverExtractor {
	return &ArchiverExtractor{Extractor: archiver.Zip{
		Compression: archiver.ZipMethodZstd, TextEncoding: "gbk",
	}, sourceArchive: sourceArchive}
}

func DetectArchive(sourceArchiveName string, sourceArchive io.Reader) (*ArchiverExtractor, error) {
	fmt, r, err := archiver.Identify(sourceArchiveName, sourceArchive)
	if err != nil {
		return nil, err
	}
	if ext, ok := fmt.(archiver.Extractor); ok {
		return NewArchive(ext, r), nil
	}
	return nil, errs.NotSupport
}

func NewArchive(extractor archiver.Extractor, sourceArchive io.Reader) *ArchiverExtractor {
	if _, ok := extractor.(archiver.Zip); ok {
		return NewZipArchive(sourceArchive)
	}
	return &ArchiverExtractor{Extractor: extractor, sourceArchive: sourceArchive}
}

type ArchiverExtractor struct {
	archiver.Extractor
	sourceArchive  io.Reader
	fileHandler    archiver.FileHandler
	pathsInArchive []string
}

// ExtractDirs 提取指定目录下的所有文件和目录
func (ae *ArchiverExtractor) ExtractDirs(ctx context.Context, dir string) ([]archiver.File, error) {
	files := make([]archiver.File, 0)
	ff := DirFilter(&files, dir)
	if ae.fileHandler != nil {
		ff = ae.fileHandler
	}
	return files, ae.Extract(ctx, ae.sourceArchive, ae.pathsInArchive, ff)
}

// ExtractFile 提取指定文件
func (ae *ArchiverExtractor) ExtractFile(ctx context.Context, filePath string) (*archiver.File, error) {
	files := make([]archiver.File, 0)
	ff := FileFilter(&files, filePath)
	if ae.fileHandler != nil {
		ff = ae.fileHandler
	}
	err := ae.Extract(ctx, ae.sourceArchive, ae.pathsInArchive, ff)
	if len(files) == 0 {
		return nil, fmt.Errorf("file not found")
	}
	return &files[0], err
}

// NoFilter 级联提取所有文件和目录
func NoFilter(files *[]archiver.File) archiver.FileHandler {
	return func(ctx context.Context, f archiver.File) error {
		*files = append(*files, f)
		return nil
	}
}

// DirFilter 仅提取指定目录下的文件和目录
func DirFilter(files *[]archiver.File, dir string) archiver.FileHandler {
	return func(ctx context.Context, f archiver.File) error {
		dirPath := f.NameInArchive
		fileDir := strings.TrimPrefix("/"+dirPath, dir)
		if (strings.Count(fileDir, "/") == 0 && len(fileDir) > 0) ||
			(strings.Count(fileDir, "/") == 1 && strings.HasSuffix(fileDir, "/")) {
			*files = append(*files, f)
		}
		return nil
	}
}

// FileFilter 仅提取指定文件
func FileFilter(files *[]archiver.File, filePath string) archiver.FileHandler {
	return func(ctx context.Context, f archiver.File) error {
		if f.IsDir() {
			return nil
		}

		if !strings.HasPrefix(filePath, "/"+path.Dir(f.NameInArchive)) {
			return stdfs.SkipDir
		}
		if filePath == "/"+f.NameInArchive {
			*files = append(*files, f)
		}
		return nil
	}
}
