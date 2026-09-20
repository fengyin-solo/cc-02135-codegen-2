// 传输审计与操作留痕页面
const API_BASE = CONFIG.API_BASE;

const PAGE_SIZE = 20;
const EXPORT_TIMEOUT_MS = 60000;

// 登录身份（与 index.html 共享同一套本地凭据，保证审计数据联通登录身份）
const TokenManager = {
    TOKEN_KEY: 'auth_token',
    USER_KEY: 'auth_user',

    save(token, username) {
        localStorage.setItem(this.TOKEN_KEY, token);
        localStorage.setItem(this.USER_KEY, username);
    },
    get() {
        return localStorage.getItem(this.TOKEN_KEY);
    },
    getUser() {
        return localStorage.getItem(this.USER_KEY);
    },
    clear() {
        localStorage.removeItem(this.TOKEN_KEY);
        localStorage.removeItem(this.USER_KEY);
    },
    async isValid() {
        const token = this.get();
        if (!token) return false;
        try {
            const response = await fetch(`${API_BASE}/refresh-token?token=${token}`, { method: 'POST' });
            return response.ok;
        } catch {
            return false;
        }
    }
};

// 页面状态：筛选 / 分页 / 当前页数据
const state = {
    page: 1,
    total: 0,
    totalPages: 1,
    items: [],
    loading: false,
};

// ---- 选择持久化 -------------------------------------------------------------
// 选择集与登录身份绑定并写入 localStorage：
// 空数据、导出中断、文件生成失败以及重新进入页面都不会丢失已选进度。
function selectionStorageKey() {
    const user = TokenManager.getUser() || 'anonymous';
    return `audit_selected_${user}`;
}

function viewStorageKey() {
    const user = TokenManager.getUser() || 'anonymous';
    return `audit_view_${user}`;
}

function getSelectedIds() {
    try {
        const raw = localStorage.getItem(selectionStorageKey());
        const ids = raw ? JSON.parse(raw) : [];
        return Array.isArray(ids) ? ids : [];
    } catch {
        return [];
    }
}

function setSelectedIds(ids) {
    localStorage.setItem(selectionStorageKey(), JSON.stringify([...new Set(ids)]));
}

function isSelected(id) {
    return getSelectedIds().includes(id);
}

function toggleId(id, checked) {
    const ids = getSelectedIds();
    const next = checked ? [...new Set([...ids, id])] : ids.filter(x => x !== id);
    setSelectedIds(next);
    renderSelectionState();
}

function clearSelection() {
    setSelectedIds([]);
    renderSelectionState();
    syncRowSelectionStyles();
    showNotice('info', '已清空选择', '之前勾选的审计记录已全部取消。');
}

function saveViewState() {
    localStorage.setItem(viewStorageKey(), JSON.stringify({
        page: state.page,
        action: document.getElementById('filterAction').value,
        result: document.getElementById('filterResult').value,
        keyword: document.getElementById('filterKeyword').value,
        format: document.getElementById('exportFormat').value,
    }));
}

function restoreViewState() {
    try {
        const raw = localStorage.getItem(viewStorageKey());
        if (!raw) return;
        const view = JSON.parse(raw);
        document.getElementById('filterAction').value = view.action || '';
        document.getElementById('filterResult').value = view.result || '';
        document.getElementById('filterKeyword').value = view.keyword || '';
        if (view.format) document.getElementById('exportFormat').value = view.format;
        state.page = Math.max(1, parseInt(view.page, 10) || 1);
    } catch {
        /* 视图状态损坏时使用默认值，不影响选择 */
    }
}

// ---- HTML 转义（防 XSS） ----------------------------------------------------
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

// ---- 动作 / 结果展示 --------------------------------------------------------
const ACTION_ICONS = {
    upload: '📥',
    download: '⬇️',
    share_download: '🔗',
    auth: '🔐',
    share_create: '✨',
    share_delete: '🗑️',
    audit_export: '📤',
};

const FAILURE_REASONS = {
    unauthorized: '未授权或登录已过期',
    invalid_credentials: '用户名或密码错误',
    file_not_found: '文件不存在',
    file_missing_on_disk: '文件在服务器上已丢失',
    invalid_path: '文件路径非法',
    blocked_extension: '文件类型被安全策略禁止',
    file_too_large: '文件大小超出限制',
    forbidden: '无权操作他人创建的对象',
    share_not_found: '分享链接不存在',
    invalid_share: '分享链接无效',
    empty_selection: '未选择任何审计记录',
    unsupported_format: '不支持的导出格式',
    too_many_records: '超出单次导出数量上限',
    invalid_ids: '选择中包含无效的记录标识',
    no_matching_records: '所选记录均已不存在或不可导出',
    generation_failed: '服务器在生成审计文件时失败',
};

function parseDetail(raw) {
    if (!raw) return null;
    try {
        return JSON.parse(raw);
    } catch {
        return { raw };
    }
}

function describeDetail(detail) {
    if (!detail) return '';
    if (typeof detail === 'string') return escapeHtml(detail);
    const parts = [];
    if (detail.reason) {
        const text = FAILURE_REASONS[detail.reason] || detail.reason;
        parts.push(`<span class="detail-reason">原因：${escapeHtml(text)}</span>`);
    }
    if (detail.size !== undefined) parts.push(`大小：${formatSize(detail.size)}`);
    if (detail.channel) parts.push(`渠道：${detail.channel === 'share_link' ? '分享链接' : '登录鉴权'}`);
    if (detail.format) parts.push(`格式：${escapeHtml(detail.format)}`);
    if (detail.selected_count !== undefined) parts.push(`选择 ${detail.selected_count} 条`);
    if (detail.generated_count !== undefined) parts.push(`生成 ${detail.generated_count} 条`);
    if (detail.max_downloads !== undefined) parts.push(`下载上限：${detail.max_downloads ?? '无限制'}`);
    if (detail.expire_hours !== undefined) parts.push(detail.expire_hours === null ? '永久有效' : `有效期 ${detail.expire_hours} 小时`);
    return parts.join('<br>');
}

function formatSize(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

function shortId(id) {
    if (!id) return '';
    return id.length > 16 ? id.slice(0, 8) + '…' : id;
}

// ---- 登录 -------------------------------------------------------------------
function showPanel(authed) {
    document.getElementById('loginRequired').style.display = authed ? 'none' : 'block';
    document.getElementById('auditPanel').style.display = authed ? 'block' : 'none';
    const bar = document.getElementById('userBar');
    if (authed) {
        const user = TokenManager.getUser();
        document.getElementById('currentUser').textContent = user;
        document.getElementById('userAvatar').textContent = user.charAt(0).toUpperCase();
        bar.classList.remove('hidden');
    } else {
        bar.classList.add('hidden');
    }
}

function logout() {
    TokenManager.clear();
    showPanel(false);
}

async function ensureAuth() {
    if (TokenManager.get() && await TokenManager.isValid()) {
        showPanel(true);
        return true;
    }
    TokenManager.clear();
    showPanel(false);
    return false;
}

document.getElementById('auditLoginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    const errorEl = document.getElementById('loginError');
    errorEl.textContent = '';

    try {
        const resp = await fetch(`${API_BASE}/auth`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });
        const result = await resp.json();
        if (resp.ok && result.success) {
            TokenManager.save(result.token, username);
            showPanel(true);
            restoreViewState();
            loadLogs();
        } else {
            errorEl.textContent = result.error || '验证失败';
        }
    } catch (err) {
        errorEl.textContent = `无法连接服务：${err.message}`;
    }
});

// ---- 提示条 -----------------------------------------------------------------
let noticeTimer = null;
function showNotice(kind, title, desc, sticky = false) {
    const el = document.getElementById('auditNotice');
    const icon = kind === 'error' ? '⚠️' : kind === 'success' ? '✅' : 'ℹ️';
    el.className = `audit-notice notice-${kind}`;
    el.innerHTML = `
        <span class="notice-icon">${icon}</span>
        <span class="notice-body">
            <span class="notice-title">${escapeHtml(title)}</span>
            <span class="notice-desc">${escapeHtml(desc)}</span>
        </span>
        <button class="notice-close" title="关闭">✕</button>`;
    el.style.display = 'flex';
    el.querySelector('.notice-close').onclick = () => { el.style.display = 'none'; };

    if (noticeTimer) clearTimeout(noticeTimer);
    if (!sticky) {
        noticeTimer = setTimeout(() => { el.style.display = 'none'; }, 8000);
    }
}

// ---- 加载审计记录 -----------------------------------------------------------
async function loadLogs() {
    if (state.loading) return;
    state.loading = true;
    const tbody = document.getElementById('auditTableBody');
    document.getElementById('auditEmpty').style.display = 'none';
    document.getElementById('auditLoading').style.display = 'block';
    tbody.innerHTML = '';

    const params = new URLSearchParams({
        page: String(state.page),
        page_size: String(PAGE_SIZE),
    });
    const action = document.getElementById('filterAction').value;
    const result = document.getElementById('filterResult').value;
    const keyword = document.getElementById('filterKeyword').value.trim();
    if (action) params.set('action', action);
    if (result) params.set('result', result);
    if (keyword) params.set('keyword', keyword);

    try {
        const resp = await fetch(`${API_BASE}/audit/logs?${params.toString()}`, {
            headers: { 'Authorization': `Bearer ${TokenManager.get()}` },
        });

        if (resp.status === 401) {
            TokenManager.clear();
            showPanel(false);
            return;
        }
        if (!resp.ok) {
            throw new Error(`请求失败（HTTP ${resp.status}）`);
        }

        const data = await resp.json();
        state.items = data.items || [];
        state.total = data.total;
        state.totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
        if (state.page > state.totalPages) {
            state.page = state.totalPages;
            saveViewState();
            state.loading = false;
            loadLogs();
            return;
        }
        renderTable();
        renderPagination();
    } catch (err) {
        // 列表加载失败同样保留已有选择，并说明原因
        document.getElementById('auditLoading').style.display = 'none';
        showNotice('error', '审计记录加载失败', `${err.message}，当前选择已保留，可重试查询。`, true);
    } finally {
        state.loading = false;
        saveViewState();
    }
}

function renderTable() {
    const tbody = document.getElementById('auditTableBody');
    const loading = document.getElementById('auditLoading');
    const empty = document.getElementById('auditEmpty');
    loading.style.display = 'none';

    if (!state.items.length) {
        tbody.innerHTML = '';
        empty.style.display = 'block';
        renderSelectionState();
        return;
    }
    empty.style.display = 'none';

    tbody.innerHTML = state.items.map(item => {
        const checked = isSelected(item.id);
        const actorTypeLabel = item.actor_type === 'guest' ? '访客' : '登录用户';
        const actor = item.actor
            ? `<span class="actor-name">${escapeHtml(item.actor)}</span>`
            : `<span class="actor-name" style="color:var(--text-secondary)">匿名访客</span>`;
        const metaParts = [`<span class="actor-type-tag">${actorTypeLabel}</span>`];
        if (item.actor_ip) metaParts.push(escapeHtml(item.actor_ip));

        const objectName = item.object_name
            ? `<span class="object-name">${escapeHtml(item.object_name)}</span>`
            : '<span class="object-name" style="color:var(--text-secondary)">—</span>';
        const objectId = item.object_id
            ? `<span class="object-id" title="${escapeHtml(item.object_id)}">${escapeHtml(item.object_type || '')}: ${escapeHtml(shortId(item.object_id))}</span>`
            : '';

        const detail = parseDetail(item.detail);
        const detailHtml = describeDetail(detail);

        return `
        <tr data-id="${item.id}" class="${checked ? 'row-selected' : ''}">
            <td class="col-check">
                <input type="checkbox" class="row-check" data-id="${item.id}"
                    ${checked ? 'checked' : ''}
                    onchange="onRowCheck(this)" aria-label="选择记录 ${item.id}">
            </td>
            <td class="col-id">${item.id}</td>
            <td class="col-action">
                <span class="action-badge action-${escapeHtml(item.action)}">
                    ${ACTION_ICONS[item.action] || '•'} ${escapeHtml(item.action_label || item.action)}
                </span>
            </td>
            <td class="col-actor">
                <span class="actor-cell">${actor}<span class="actor-meta">${metaParts.join(' ')}</span></span>
            </td>
            <td><span class="object-cell">${objectName}${objectId}</span></td>
            <td class="col-result">
                <span class="result-badge result-${item.result}">
                    ${item.result === 'success' ? '✓ 成功' : '✕ 失败'}
                </span>
            </td>
            <td class="detail-cell">${detailHtml}</td>
            <td class="col-time">${escapeHtml(item.occurred_at)}</td>
        </tr>`;
    }).join('');

    renderSelectionState();
}

function renderPagination() {
    document.getElementById('currentPage').textContent = state.page;
    document.getElementById('totalPages').textContent = state.totalPages;
    document.getElementById('totalCount').textContent = state.total;
    document.getElementById('prevPage').disabled = state.page <= 1;
    document.getElementById('nextPage').disabled = state.page >= state.totalPages;
}

function renderSelectionState() {
    const ids = getSelectedIds();
    document.getElementById('selectedCount').textContent = ids.length;

    const exportBtn = document.getElementById('exportBtn');
    exportBtn.disabled = ids.length === 0;

    // 本页全选框状态：当前页全部在选择集中则勾选
    const pageIds = state.items.map(i => i.id);
    const allChecked = pageIds.length > 0 && pageIds.every(id => ids.includes(id));
    const someChecked = pageIds.some(id => ids.includes(id));
    const selectAll = document.getElementById('selectAllPage');
    selectAll.checked = allChecked;
    selectAll.indeterminate = someChecked && !allChecked;

    syncRowSelectionStyles();
}

function syncRowSelectionStyles() {
    document.querySelectorAll('#auditTableBody tr').forEach(tr => {
        const id = parseInt(tr.dataset.id, 10);
        tr.classList.toggle('row-selected', isSelected(id));
        const cb = tr.querySelector('.row-check');
        if (cb) cb.checked = isSelected(id);
    });
}

function onRowCheck(checkbox) {
    const id = parseInt(checkbox.dataset.id, 10);
    toggleId(id, checkbox.checked);
    const tr = checkbox.closest('tr');
    if (tr) tr.classList.toggle('row-selected', checkbox.checked);
}

function toggleSelectPage(checked) {
    const pageIds = state.items.map(i => i.id);
    let ids = getSelectedIds();
    if (checked) {
        ids = [...new Set([...ids, ...pageIds])];
    } else {
        ids = ids.filter(id => !pageIds.includes(id));
    }
    setSelectedIds(ids);
    renderTable();
}

// ---- 筛选与分页 -------------------------------------------------------------
function applyFilters() {
    state.page = 1;
    loadLogs();
}

function resetFilters() {
    document.getElementById('filterAction').value = '';
    document.getElementById('filterResult').value = '';
    document.getElementById('filterKeyword').value = '';
    state.page = 1;
    loadLogs();
}

function changePage(delta) {
    const next = state.page + delta;
    if (next < 1 || next > state.totalPages) return;
    state.page = next;
    loadLogs();
}

// 回车触发检索
document.getElementById('filterKeyword').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') applyFilters();
});
document.getElementById('exportFormat').addEventListener('change', saveViewState);

// ---- 导出 -------------------------------------------------------------------
function showLoading(text) {
    document.getElementById('loadingText').textContent = text;
    document.getElementById('loadingOverlay').classList.add('active');
}
function hideLoading() {
    document.getElementById('loadingOverlay').classList.remove('active');
}

async function exportSelected() {
    const ids = getSelectedIds();
    const format = document.getElementById('exportFormat').value;

    if (!ids.length) {
        // 空数据 / 空选择：不发起请求，保留当前选择并说明原因
        showNotice('error', '没有可导出的记录',
            '当前未勾选任何审计记录，请先在列表中勾选后再导出；已有选择不会被清除。');
        return;
    }

    const btn = document.getElementById('exportBtn');
    btn.disabled = true;
    showLoading(`正在生成审计文件（已选 ${ids.length} 条）...`);

    // 用 AbortController 识别“导出中断”：超时或网络中止时保留选择
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), EXPORT_TIMEOUT_MS);

    let response;
    try {
        response = await fetch(`${API_BASE}/audit/export`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${TokenManager.get()}`,
            },
            body: JSON.stringify({ ids, format }),
            signal: controller.signal,
        });
    } catch (err) {
        clearTimeout(timer);
        hideLoading();
        btn.disabled = false;
        const reason = err.name === 'AbortError'
            ? `导出请求超过 ${EXPORT_TIMEOUT_MS / 1000} 秒被中断`
            : `网络中断：${err.message}`;
        // 导出中断：保留当前选择并说明原因，允许直接重试
        showNotice('error', '导出中断，当前选择已保留',
            `${reason}。已选 ${ids.length} 条记录未被清除，请检查网络后重新点击导出。`, true);
        return;
    }
    clearTimeout(timer);

    if (!response.ok) {
        hideLoading();
        btn.disabled = false;

        // 文件生成失败 / 参数问题 / 未授权：解析后端原因，保留选择
        let reasonText = `服务返回错误（HTTP ${response.status}）`;
        let reasonKey = '';
        try {
            const body = await response.json();
            reasonText = body.error || reasonText;
            reasonKey = body.reason || '';
        } catch {
            /* 非 JSON 响应时沿用 HTTP 状态描述 */
        }

        if (response.status === 401) {
            TokenManager.clear();
            showPanel(false);
            showNotice('error', '登录已过期', '为保障审计数据安全，请重新验证身份；勾选记录已按身份保留。', true);
            return;
        }

        const advise = {
            empty_selection: '请先勾选记录后重试。',
            no_matching_records: '请重新查询列表核对记录是否仍然存在，勾选状态未被清除。',
            invalid_ids: '选择中可能包含已失效的记录，请刷新列表核对后重试。',
            generation_failed: '服务端文件生成失败，所选记录与勾选状态均已保留，可稍后重试或更换格式。',
            too_many_records: '请减少单次勾选数量后分批导出。',
            unsupported_format: '请在导出格式下拉框中选择 CSV 或 JSON。',
        };
        const tip = advise[reasonKey] || (FAILURE_REASONS[reasonKey] ? `${FAILURE_REASONS[reasonKey]}。` : '');
        const desc = `${reasonText}${tip ? ' ' + tip : ''}（已选 ${ids.length} 条，选择已保留）`;
        showNotice('error', '审计文件生成失败', desc, true);
        return;
    }

    // 成功：拿到文件流并触发下载
    try {
        const blob = await response.blob();
        const filename = extractFilename(response.headers.get('Content-Disposition'))
            || `audit-trails.${format}`;
        triggerDownload(blob, filename);

        const count = response.headers.get('X-Audit-Count');
        const missing = response.headers.get('X-Audit-Missing-Count');
        let msg = `已导出 ${count || ids.length} 条审计记录到文件 ${filename}。`;
        if (missing && missing !== '0') {
            msg += ` 另有 ${missing} 条所选记录已不存在，未包含在文件中。`;
        }
        msg += ' 勾选状态已保留，可切换格式再次导出或清空选择。';
        showNotice('success', '审计文件已生成并开始下载', msg);
    } catch (err) {
        // 浏览器侧保存文件失败，也视为导出中断，保留选择
        showNotice('error', '文件保存中断，当前选择已保留',
            `${err.message}。已选 ${ids.length} 条记录未被清除，可重试导出。`, true);
    } finally {
        hideLoading();
        btn.disabled = false;
        // 刷新列表以呈现本次“审计导出”留痕（保持当前筛选与页码）
        loadLogs();
    }
}

function extractFilename(disposition) {
    if (!disposition) return null;
    const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
    if (utf8Match) {
        try { return decodeURIComponent(utf8Match[1]); } catch { return utf8Match[1]; }
    }
    const match = disposition.match(/filename="?([^";\n]+)"?/i);
    return match ? match[1] : null;
}

function triggerDownload(blob, filename) {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    // 稍延后回收，确保浏览器已接管下载流
    setTimeout(() => window.URL.revokeObjectURL(url), 1000);
}

// ---- 启动 -------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
    if (TokenManager.get() && !(await TokenManager.isValid())) {
        TokenManager.clear();
    }
    if (await ensureAuth()) {
        restoreViewState();
        loadLogs();
    }
});
