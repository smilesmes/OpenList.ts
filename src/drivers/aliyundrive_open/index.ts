/**
 * 阿里云盘驱动（AliyundriveOpen）— 对齐 OpenListTeam/OpenList-Worker 实现。
 *
 * 移植来源：OpenList-Worker 的
 *   src/backend/drivers/aliyundrive_open/{types,util,driver}.ts
 *
 * 与旧版的差异（本次更新的核心）：
 *   1. 接口域名换成 openapi.aliyundrive.com + /adrive/v1.0（旧版是
 *      open.aliyundrive.com/adrive/v1.0 + auth.aliyundrive.com/v2/account/token）。
 *   2. 取 token 改为三级策略：
 *        a) 在线 API 中转（GET + query，多个备用地址轮询）
 *        b) 直连 OAuth refresh（openapi.aliyundrive.com/oauth/access_token）
 *        c) 全部失败时抛出汇总错误（带可操作的排查提示）
 *   3. 端点全部改为 /openFile/*（list / get / getDownloadUrl / create / update /
 *      recyclebin / delete / move / copy / complete）。
 *   4. 新增 drive_type（resource / backup / default）与 drive_id 显式指定，
 *      并按 UserNotAllowedAccessDrive 自动重解析 drive_id。
 *   5. 新增 alipan_type（alipanQR / alipanTV）决定在线 API 的 driver_txt。
 *   6. 新增 remove_way（trash / delete）决定删除走回收站还是直删。
 *   7. api_url_address 在发出凭据前做 SSRF 校验（utils/ssrf）。
 *
 * 路径解析：云盘 API 只认 file_id，因此按路径逐段 list 父目录找子项，
 * 结果缓存在请求级 pathFileIdCache（Worker 每次请求新建实例，缓存天然短命）。
 */
import { Driver, DriverConfig, DriverItem, Obj, ListResult, LinkResult } from '../types';
import { registerDriver } from '../registry';
import { createFileObj, createDirObj } from '../base';
import { assertSafeUrl } from '../../utils/ssrf';

// ============================================================================
// 配置与类型
// ============================================================================

const ALI_OPEN_API = 'https://openapi.aliyundrive.com/adrive/v1.0';
const ALI_OAUTH_TOKEN_URL = 'https://openapi.aliyundrive.com/oauth/access_token';
/** 上游内置的公共 Client ID（未自带 client_id 时使用） */
const DEFAULT_CLIENT_ID = '25ab4837190e48718a28f80073574a4d';

/** 在线 API 中转备用地址（顺序即优先级） */
const ONLINE_TOKEN_APIS = [
  'https://api.oplist.org/alicloud/renewapi',
  'https://api.oplist.org/ali_open/token',
  'https://api.oplist.org/aliyundrive/token',
  'https://api.alist.nn.ci/alist/ali_open/token',
  'https://api.alist.nn.ci/aliyundrive/token',
  'https://api-sam.oplist.org/aliyundrive/token',
];

export const aliyundriveOpenConfig: DriverConfig = {
  name: 'AliyundriveOpen',
  label: '阿里云盘 Open',
  local_sort: true,
  only_proxy: false,
  no_cache: false,
  no_upload: false,
  default_root: 'root',
};

export const aliyundriveOpenAdditional: DriverItem[] = [
  { name: 'refresh_token', type: 'text', default: '', options: '', required: true, help: 'Refresh Token（必填）' },
  { name: 'drive_type', type: 'select', default: 'resource', options: 'resource,backup,default', required: true, help: '要挂载的盘类型' },
  { name: 'drive_id', type: 'string', default: '', options: '', required: false, help: '留空自动解析' },
  { name: 'root_folder_id', type: 'string', default: 'root', options: '', required: false, help: '根目录 ID' },
  { name: 'order_by', type: 'select', default: 'updated_at', options: 'updated_at,name,size,created_at', required: false, help: '排序字段' },
  { name: 'order_direction', type: 'select', default: 'DESC', options: 'DESC,ASC', required: false, help: '排序方向' },
  { name: 'api_url_address', type: 'string', default: 'https://api.oplist.org/alicloud/renewapi', options: '', required: false, help: '在线 API 中转地址（留空用内置列表）' },
  { name: 'alipan_type', type: 'select', default: 'alipanQR', options: 'alipanQR,alipanTV', required: false, help: '在线 API 的 driver_txt 类型' },
  { name: 'client_id', type: 'string', default: '', options: '', required: false, help: '留空用内置公共 Client ID' },
  { name: 'client_secret', type: 'string', default: '', options: '', required: false, help: '直连 OAuth 时必填' },
  { name: 'remove_way', type: 'select', default: 'trash', options: 'trash,delete', required: false, help: '删除方式：回收站 / 直接删除' },
];

interface AliyunOpenAddition {
  refresh_token?: string;
  drive_type?: 'resource' | 'backup' | 'default';
  drive_id?: string;
  root_folder_id?: string;
  order_by?: string;
  order_direction?: string;
  api_url_address?: string;
  alipan_type?: 'alipanQR' | 'alipanTV';
  client_id?: string;
  client_secret?: string;
  remove_way?: 'trash' | 'delete';
}

interface AliyunTokenResp {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
}

interface AliyunFileItem {
  file_id: string;
  name: string;
  type?: 'file' | 'folder' | string;
  size?: number;
  created_at?: string;
  updated_at?: string;
  thumbnail?: string;
  download_url?: string;
}

interface AliyunDriveInfo {
  default_drive_id?: string;
  resource_drive_id?: string;
  backup_drive_id?: string;
}

// ============================================================================
// API 客户端
// ============================================================================

class AliyunOpenClient {
  private cfg: AliyunOpenAddition;
  private accessToken = '';
  private refreshTokenVal = '';
  private driveId = '';
  private tokenExpiresAt = 0;

  constructor(cfg: AliyunOpenAddition) {
    this.cfg = cfg;
    this.refreshTokenVal = (cfg.refresh_token || '').trim();
    this.driveId = (cfg.drive_id || '').trim();
  }

  async init(): Promise<void> {
    if (!this.refreshTokenVal) {
      console.warn('[AliyundriveOpen] refresh_token is empty, skipping init.');
      return;
    }
    await this.refreshAccessToken();
    if (!this.driveId) {
      await this.resolveDriveId();
    }
  }

  getRootFolderId(): string {
    return (this.cfg.root_folder_id || '').trim() || 'root';
  }

  getDriveId(): string {
    return this.driveId;
  }

  /** 解析 drive_id：按 drive_type 从 getDriveInfo 里挑对应字段 */
  private async resolveDriveId(forceResource = false): Promise<void> {
    if (!forceResource && this.cfg.drive_id && this.cfg.drive_id.trim()) {
      this.driveId = this.cfg.drive_id.trim();
      return;
    }
    const info = await this.request<AliyunDriveInfo>('/user/getDriveInfo', {});
    const driveType = forceResource ? 'resource' : this.cfg.drive_type || 'resource';

    let picked = '';
    if (driveType === 'resource' && info.resource_drive_id) {
      picked = info.resource_drive_id;
    } else if (driveType === 'backup' && info.backup_drive_id) {
      picked = info.backup_drive_id;
    } else if (driveType === 'default' && info.default_drive_id) {
      picked = info.default_drive_id;
    }
    if (!picked) {
      picked =
        info.default_drive_id ||
        info.resource_drive_id ||
        info.backup_drive_id ||
        '';
    }
    this.driveId = picked;
    console.log(`[AliyundriveOpen] Resolved drive_id: ${this.driveId} (driveType: ${driveType})`);
  }

  /**
   * 刷新 access_token。
   * 策略 1：在线 API 中转（多个备用地址轮询）
   * 策略 2：直连 OAuth（需要 client_id + client_secret）
   */
  async refreshAccessToken(): Promise<void> {
    const token = this.refreshTokenVal.trim();
    if (!token) {
      throw new Error('[AliyundriveOpen] refresh_token is required');
    }

    // ---- 策略 1：在线 API 中转 ----
    const onlineApis: string[] = [];
    const custom = (this.cfg.api_url_address || '').trim();
    if (custom) {
      try {
        assertSafeUrl(custom, 'AliyundriveOpen api_url_address');
        onlineApis.push(custom);
      } catch (e: any) {
        console.warn(`[AliyundriveOpen] Skipping unsafe api_url_address: ${e.message}`);
      }
    }
    onlineApis.push(...ONLINE_TOKEN_APIS);

    const driverTxt = this.cfg.alipan_type === 'alipanTV' ? 'alicloud_tv' : 'alicloud_qr';

    for (const apiUrl of onlineApis) {
      try {
        const params = new URLSearchParams({
          refresh_ui: token,
          refresh_token: token,
          server_use: 'true',
          driver_txt: driverTxt,
        });
        const res = await fetch(`${apiUrl}?${params.toString()}`, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
        });
        if (!res.ok) {
          throw new Error(`[Status ${res.status}]`);
        }
        const data: any = await res.json();
        const newAccess: string = data.access_token || data.data?.access_token || '';
        const newToken: string = data.refresh_token || data.data?.refresh_token || '';
        if (!newAccess) {
          throw new Error(`Empty access_token: ${JSON.stringify(data).slice(0, 200)}`);
        }
        this.accessToken = newAccess;
        if (newToken) this.refreshTokenVal = newToken;
        this.tokenExpiresAt = Date.now() + (Number(data.expires_in) || 7200) * 1000 - 60_000;
        return;
      } catch (err: any) {
        console.warn(`[AliyundriveOpen] Online API '${apiUrl}' failed: ${err.message}`);
      }
    }

    // ---- 策略 2：直连 OAuth ----
    const clientId = (this.cfg.client_id || '').trim() || DEFAULT_CLIENT_ID;
    const clientSecret = (this.cfg.client_secret || '').trim();
    try {
      const payload: Record<string, string> = {
        grant_type: 'refresh_token',
        refresh_token: token,
        client_id: clientId,
      };
      if (clientSecret) payload.client_secret = clientSecret;

      const res = await fetch(ALI_OAUTH_TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        throw new Error(`[Status ${res.status}] ${text.slice(0, 200)}`);
      }
      const data: AliyunTokenResp = await res.json();
      if (!data.access_token) {
        throw new Error(`Invalid response: ${JSON.stringify(data).slice(0, 200)}`);
      }
      this.accessToken = data.access_token;
      if (data.refresh_token) this.refreshTokenVal = data.refresh_token;
      this.tokenExpiresAt = Date.now() + (Number(data.expires_in) || 7200) * 1000 - 60_000;
      return;
    } catch (err: any) {
      console.warn(`[AliyundriveOpen] Direct OAuth failed: ${err.message}`);
    }

    throw new Error(
      '[AliyundriveOpen] All token refresh strategies failed. Check: ' +
        '1) refresh_token is valid and not expired, ' +
        '2) api_url_address is reachable, ' +
        '3) if using direct OAuth, client_id and client_secret are correct.',
    );
  }

  private async ensureToken(): Promise<void> {
    if (!this.accessToken || Date.now() >= this.tokenExpiresAt) {
      await this.refreshAccessToken();
    }
  }

  /** 统一 API 调用入口：自动带 token、401 自动刷新重试一次、SSRF 校验 */
  private async request<T = any>(path: string, body: any, retry = true): Promise<T> {
    await this.ensureToken();
    const url = path.startsWith('http') ? path : `${ALI_OPEN_API}${path}`;
    try {
      assertSafeUrl(url, 'AliyundriveOpen request');
    } catch (e: any) {
      throw new Error(`[AliyundriveOpen] blocked unsafe URL: ${e.message}`);
    }

    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.accessToken}`,
      },
      body: JSON.stringify(body),
    });

    if (res.status === 401 && retry) {
      await this.refreshAccessToken();
      return this.request<T>(path, body, false);
    }
    if (!res.ok) {
      const err = await res.text().catch(() => '');
      throw new Error(`[AliyundriveOpen] API error [${res.status}] ${path}: ${err.slice(0, 300)}`);
    }
    return (await res.json()) as T;
  }

  // ---- 读 ----

  async listFiles(parentFileId: string): Promise<AliyunFileItem[]> {
    if (!this.driveId) await this.resolveDriveId();
    const items: AliyunFileItem[] = [];
    let marker: string | undefined;

    do {
      const body: Record<string, any> = {
        drive_id: this.driveId,
        parent_file_id: parentFileId,
        limit: 100,
        order_by: this.cfg.order_by || 'updated_at',
        order_direction: this.cfg.order_direction || 'DESC',
      };
      if (marker) body.marker = marker;

      let resp: any;
      try {
        resp = await this.request<any>('/openFile/list', body);
      } catch (err: any) {
        if (String(err?.message || '').includes('UserNotAllowedAccessDrive')) {
          console.warn(
            `[AliyundriveOpen] UserNotAllowedAccessDrive for drive ${this.driveId}, re-resolving...`,
          );
          await this.resolveDriveId(true);
          body.drive_id = this.driveId;
          resp = await this.request<any>('/openFile/list', body);
        } else {
          throw err;
        }
      }
      items.push(...((resp.items || []) as AliyunFileItem[]));
      marker = resp.next_marker || undefined;
    } while (marker);

    return items;
  }

  async getFile(fileId: string): Promise<AliyunFileItem> {
    if (!this.driveId) await this.resolveDriveId();
    return this.request<AliyunFileItem>('/openFile/get', {
      drive_id: this.driveId,
      file_id: fileId,
    });
  }

  async getDownloadUrl(fileId: string): Promise<string> {
    if (!this.driveId) await this.resolveDriveId();
    const resp = await this.request<any>('/openFile/getDownloadUrl', {
      drive_id: this.driveId,
      file_id: fileId,
      expire_sec: 14400,
    });
    return resp.url || resp.download_url || '';
  }

  // ---- 写 ----

  async mkdir(parentFileId: string, name: string): Promise<void> {
    await this.request('/openFile/create', {
      drive_id: this.driveId,
      parent_file_id: parentFileId,
      name,
      type: 'folder',
      check_name_mode: 'refuse',
    });
  }

  async rename(fileId: string, newName: string): Promise<void> {
    await this.request('/openFile/update', {
      drive_id: this.driveId,
      file_id: fileId,
      name: newName,
      check_name_mode: 'refuse',
    });
  }

  async remove(fileId: string): Promise<void> {
    const way = this.cfg.remove_way || 'trash';
    await this.request(way === 'trash' ? '/openFile/recyclebin' : '/openFile/delete', {
      drive_id: this.driveId,
      file_id: fileId,
    });
  }

  async move(fileId: string, toParentFileId: string): Promise<void> {
    await this.request('/openFile/move', {
      drive_id: this.driveId,
      file_id: fileId,
      to_parent_file_id: toParentFileId,
      check_name_mode: 'refuse',
    });
  }

  async copy(fileId: string, toParentFileId: string): Promise<void> {
    await this.request('/openFile/copy', {
      drive_id: this.driveId,
      file_id: fileId,
      to_parent_file_id: toParentFileId,
      auto_rename: true,
    });
  }

  /** 单分片上传（对齐 Worker 实现：part_info_list 只带 part_number 1） */
  async putFile(parentFileId: string, filename: string, content: ArrayBuffer): Promise<void> {
    const size = content.byteLength;
    const createResp = await this.request<any>('/openFile/create', {
      drive_id: this.driveId,
      parent_file_id: parentFileId,
      name: filename,
      type: 'file',
      size,
      check_name_mode: 'auto_rename',
      part_info_list: [{ part_number: 1 }],
    });

    const uploadUrl = createResp.part_info_list?.[0]?.upload_url;
    if (!uploadUrl) {
      throw new Error('[AliyundriveOpen] create response has no upload_url');
    }
    const putRes = await fetch(uploadUrl, { method: 'PUT', body: content });
    if (!putRes.ok) {
      throw new Error(`[AliyundriveOpen] Upload failed: ${putRes.status}`);
    }
    await this.request('/openFile/complete', {
      drive_id: this.driveId,
      file_id: createResp.file_id,
      upload_id: createResp.upload_id,
    });
  }
}

// ============================================================================
// 驱动实现
// ============================================================================

/** 云盘条目 -> 统一 Obj */
function toObj(f: AliyunFileItem): Obj {
  const isDir = f.type === 'folder';
  if (isDir) {
    return createDirObj({
      name: f.name,
      modified: f.updated_at || f.created_at,
      created: f.created_at,
      id: f.file_id,
    });
  }
  return createFileObj({
    name: f.name,
    size: f.size || 0,
    modified: f.updated_at || f.created_at,
    created: f.created_at,
    thumb: f.thumbnail,
    id: f.file_id,
  });
}

export class AliyundriveOpenDriver implements Driver {
  private cfg: AliyunOpenAddition = {};
  private client: AliyunOpenClient | null = null;
  private pathFileIdCache = new Map<string, string>();

  config(): DriverConfig {
    return aliyundriveOpenConfig;
  }

  async init(config: Record<string, any>): Promise<void> {
    this.cfg = (config || {}) as AliyunOpenAddition;
    this.pathFileIdCache.clear();
    this.client = new AliyunOpenClient(this.cfg);
    await this.client.init();
  }

  /** 兼容 olts 的调用形态：每个方法都会再传一次 cfg，这里合并一次。 */
  private c(cfg?: Record<string, any>): AliyunOpenClient {
    if (cfg && Object.keys(cfg).length > 0) {
      const merged: AliyunOpenAddition = { ...this.cfg, ...(cfg as AliyunOpenAddition) };
      if (!this.client || merged.refresh_token !== this.cfg.refresh_token) {
        this.cfg = merged;
        this.client = new AliyunOpenClient(this.cfg);
      }
    }
    if (!this.client) {
      this.client = new AliyunOpenClient(this.cfg);
    }
    return this.client;
  }

  /**
   * 把虚拟路径逐段解析成 file_id。
   * 云盘 API 只认 id，所以按层级 list 父目录里找同名的子项；每段结果都缓存。
   */
  private async resolveFileId(client: AliyunOpenClient, path: string): Promise<string> {
    const clean = String(path || '')
      .split('/')
      .filter(Boolean)
      .join('/');
    if (!clean) return client.getRootFolderId();

    const cachedRoot = this.pathFileIdCache.get(clean);
    if (cachedRoot) return cachedRoot;

    const parts = clean.split('/');
    let currentId = client.getRootFolderId();

    for (let i = 0; i < parts.length; i++) {
      const rawPart = parts[i];
      let decodedPart = rawPart;
      try {
        decodedPart = decodeURIComponent(rawPart);
      } catch {
        decodedPart = rawPart;
      }

      const subPath = parts.slice(0, i + 1).join('/');
      const cached = this.pathFileIdCache.get(subPath);
      if (cached) {
        currentId = cached;
        continue;
      }

      const items = await client.listFiles(currentId);
      const target = items.find(
        (f) => f.name === rawPart || f.name === decodedPart || f.file_id === rawPart,
      );
      if (!target) {
        throw new Error(`Not found: /${subPath}`);
      }
      currentId = target.file_id;
      this.pathFileIdCache.set(subPath, currentId);
    }

    return currentId;
  }

  async list(path: string, config: Record<string, any>): Promise<ListResult> {
    const client = this.c(config);
    const folderId = await this.resolveFileId(client, path);
    const files = await client.listFiles(folderId);
    const content = files.map(toObj);
    return { content, total: content.length };
  }

  async get(path: string, config: Record<string, any>): Promise<Obj> {
    const client = this.c(config);
    const fileId = await this.resolveFileId(client, path);

    try {
      const file = await client.getFile(fileId);
      return toObj(file);
    } catch {
      // 兜底：路径可能是不在其父目录列表里的文件夹（例如存储根），
      // 用「能否列目录」来判定是不是文件夹。
      try {
        await client.listFiles(fileId);
        const parts = String(path).split('/').filter(Boolean);
        return createDirObj({
          name: parts[parts.length - 1] || 'root',
          id: fileId,
        });
      } catch {
        const parts = String(path).split('/').filter(Boolean);
        return createFileObj({
          name: parts[parts.length - 1] || 'file',
          id: fileId,
        });
      }
    }
  }

  async link(path: string, config: Record<string, any>): Promise<LinkResult> {
    const client = this.c(config);
    const fileId = await this.resolveFileId(client, path);
    const url = await client.getDownloadUrl(fileId);
    if (!url) {
      throw new Error(`[AliyundriveOpen] empty download url for '${path}'`);
    }
    // 阿里云盘直链对部分客户端会校验 UA / Referer，这里不做强制代理，
    // 由存储的 web_proxy / webdav_policy 决定是否走 /p 转发。
    return { url };
  }

  async mkdir(path: string, config: Record<string, any>): Promise<void> {
    const client = this.c(config);
    const parts = String(path).split('/').filter(Boolean);
    const name = parts.pop();
    if (!name) throw new Error('[AliyundriveOpen] mkdir: empty name');
    const parentPath = '/' + parts.join('/');
    const parentId = await this.resolveFileId(client, parentPath);
    await client.mkdir(parentId, name);
  }

  async rename(path: string, newName: string, config: Record<string, any>): Promise<void> {
    const client = this.c(config);
    const fileId = await this.resolveFileId(client, path);
    await client.rename(fileId, newName);
    // 路径映射已失效，清掉缓存避免后续命中旧 id
    this.pathFileIdCache.clear();
  }

  async copy(src: string, dst: string, config: Record<string, any>): Promise<void> {
    const client = this.c(config);
    const srcId = await this.resolveFileId(client, src);
    // olts/Worker 调用约定：dst 是目标完整路径（含文件名），这里取父目录
    const dstParts = String(dst).split('/').filter(Boolean);
    dstParts.pop();
    const dstParentId = await this.resolveFileId(client, '/' + dstParts.join('/'));
    await client.copy(srcId, dstParentId);
  }

  async move(src: string, dst: string, config: Record<string, any>): Promise<void> {
    const client = this.c(config);
    const srcId = await this.resolveFileId(client, src);
    const dstParts = String(dst).split('/').filter(Boolean);
    dstParts.pop();
    const dstParentId = await this.resolveFileId(client, '/' + dstParts.join('/'));
    await client.move(srcId, dstParentId);
    this.pathFileIdCache.clear();
  }

  async remove(path: string, config: Record<string, any>): Promise<void> {
    const client = this.c(config);
    const fileId = await this.resolveFileId(client, path);
    await client.remove(fileId);
    this.pathFileIdCache.clear();
  }

  async put(
    path: string,
    file: ArrayBuffer,
    _contentType: string,
    config: Record<string, any>,
  ): Promise<void> {
    const client = this.c(config);
    const parts = String(path).split('/').filter(Boolean);
    const name = parts.pop() || 'upload';
    const parentId = await this.resolveFileId(client, '/' + parts.join('/'));
    await client.putFile(parentId, name, file);
  }
}

registerDriver(AliyundriveOpenDriver, aliyundriveOpenConfig, aliyundriveOpenAdditional);
