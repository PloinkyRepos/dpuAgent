const SECRET_ROLES = ['access', 'read', 'write'];
const CONFIDENTIAL_ROLES = ['access', 'read', 'comment', 'write'];
const ROLE_DESCRIPTIONS = Object.freeze({
    secret: {
        access: 'Can reference and use the secret operationally, without seeing its value.',
        read: 'Can view the secret value in the UI.',
        write: 'Can update the secret value and manage its usage.'
    },
    confidential: {
        access: 'Can see that the item exists and access its record, without viewing content.',
        read: 'Can open and read the content.',
        comment: 'Can add annotations and manage own comments, without edit permission.',
        write: 'Can modify, rename, delete, and create children where applicable.'
    }
});

function escapeHtml(value = '') {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function parseToolResult(payload) {
    if (!payload) return null;
    if (typeof payload !== 'string') {
        if (Object.prototype.hasOwnProperty.call(payload, 'json')) {
            return payload.json;
        }
        const blocks = Array.isArray(payload.content) ? payload.content : null;
        if (blocks) {
            const jsonBlock = blocks.find((block) => block?.type === 'json' && block.json !== undefined);
            if (jsonBlock) return jsonBlock.json;
            const textBlock = blocks.find((block) => block?.type === 'text' && typeof block.text === 'string');
            if (textBlock?.text) {
                try {
                    return JSON.parse(textBlock.text);
                } catch {
                    return null;
                }
            }
        }
        return payload;
    }
    try {
        return JSON.parse(payload);
    } catch {
        return null;
    }
}

async function callDpuTool(toolName, args = {}) {
    const client = window.webSkel?.appServices?.getClient?.('dpuAgent');
    if (!client || typeof client.callTool !== 'function') {
        throw new Error('DPU agent is not available.');
    }
    const result = await client.callTool(toolName, args);
    const parsed = parseToolResult(result);
    if (!parsed || typeof parsed !== 'object') {
        throw new Error(`Invalid DPU response for ${toolName}.`);
    }
    if (parsed.ok === false) {
        throw new Error(parsed.error || `DPU call failed: ${toolName}`);
    }
    return parsed;
}

function isNonEmptyString(value) {
    return typeof value === 'string' && value.trim().length > 0;
}

async function fetchLocalUsers(agentName = '') {
    const safeAgent = String(agentName || '').trim();
    if (!safeAgent) {
        return [];
    }
    const response = await fetch(`/auth/local-users?agent=${encodeURIComponent(safeAgent)}`, {
        credentials: 'include',
        headers: {
            Accept: 'application/json'
        }
    });
    if (!response.ok) {
        return [];
    }
    const payload = await response.json().catch(() => ({}));
    return Array.isArray(payload?.users) ? payload.users : [];
}

function normalizePrincipalVariants(value = '') {
    const normalized = String(value || '').trim();
    if (!normalized) {
        return [];
    }
    const values = [normalized];
    if (normalized.startsWith('user:local:')) {
        const username = normalized.slice('user:local:'.length).trim();
        if (username && !values.includes(username)) {
            values.push(username);
        }
    } else if (!normalized.includes('@') && !normalized.startsWith('user:')) {
        const localPrincipal = `user:local:${normalized}`;
        if (!values.includes(localPrincipal)) {
            values.push(localPrincipal);
        }
    }
    return values;
}

function principalsMatch(left = '', right = '') {
    const leftVariants = normalizePrincipalVariants(left);
    const rightVariants = normalizePrincipalVariants(right);
    if (!leftVariants.length || !rightVariants.length) {
        return false;
    }
    return leftVariants.some((value) => rightVariants.includes(value));
}

export class DpuPermissionsModal {
    constructor(element, invalidate) {
        this.element = element;
        this.invalidate = invalidate;
        this.state = {
            kind: String(element.dataset.kind || '').trim(),
            id: String(element.dataset.id || '').trim(),
            key: String(element.dataset.key || '').trim(),
            path: String(element.dataset.path || '').trim(),
            name: String(element.dataset.name || '').trim(),
            agent: String(element.dataset.agent || '').trim(),
            actorId: '',
            ownerId: '',
            role: '',
            acl: [],
            identities: [],
            pickerOpen: false,
            busy: false,
            changed: false,
            status: '',
            statusType: ''
        };
        this.invalidate();
    }

    beforeRender() {}

    async afterRender() {
        this.cacheElements();
        this.bindPickerEvents();
        this.renderSkeleton();
        await this.loadData();
    }

    cacheElements() {
        this.summaryEl = this.element.querySelector('#dpuPermissionsSummary');
        this.statusEl = this.element.querySelector('#dpuPermissionsStatus');
        this.listEl = this.element.querySelector('#dpuPermissionsList');
        this.grantSectionEl = this.element.querySelector('#dpuPermissionsGrantSection');
        this.legendEl = this.element.querySelector('#dpuPermissionsLegend');
        this.formEl = this.element.querySelector('#dpuPermissionsForm');
        this.principalInput = this.element.querySelector('#dpuPermissionPrincipal');
        this.suggestionsEl = this.element.querySelector('#dpuPermissionSuggestions');
        this.roleSelect = this.element.querySelector('#dpuPermissionRole');
    }

    bindPickerEvents() {
        if (!this.principalInput) return;
        this.principalInput.addEventListener('input', () => {
            this.selectedPrincipal = '';
            this.state.pickerOpen = true;
            this.renderIdentitySuggestions();
        });
        this.principalInput.addEventListener('focus', () => {
            this.state.pickerOpen = true;
            this.renderIdentitySuggestions();
        });
        this.principalInput.addEventListener('blur', () => {
            window.setTimeout(() => this.hideIdentitySuggestions(), 120);
        });
    }

    getRoleOptions() {
        return this.state.kind === 'secret' ? SECRET_ROLES : CONFIDENTIAL_ROLES;
    }

    isOwner() {
        return principalsMatch(this.state.actorId, this.state.ownerId);
    }

    setStatus(message = '', type = '') {
        this.state.status = message;
        this.state.statusType = type;
        this.renderStatus();
    }

    renderSkeleton() {
        this.renderRoleOptions();
        this.renderRoleLegend();
        this.renderSummary();
        this.renderStatus();
        this.renderAcl();
        this.renderIdentitySuggestions();
        this.updateFormState();
    }

    renderRoleOptions() {
        if (!this.roleSelect) return;
        const options = this.getRoleOptions();
        this.roleSelect.innerHTML = options.map((role) => `<option value="${role}">${role}</option>`).join('');
    }

    renderRoleLegend() {
        if (!this.legendEl) return;
        const descriptionMap = this.state.kind === 'secret' ? ROLE_DESCRIPTIONS.secret : ROLE_DESCRIPTIONS.confidential;
        const options = this.getRoleOptions();
        this.legendEl.innerHTML = `
            <div class="dpu-permissions-legend-title">Role guide</div>
            <div class="dpu-permissions-legend-list">
                ${options.map((role) => `
                    <div class="dpu-permissions-legend-item">
                        <div class="dpu-permissions-legend-role">${role}</div>
                        <div class="dpu-permissions-legend-description">${descriptionMap[role] || ''}</div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    renderSummary() {
        if (!this.summaryEl) return;
        const resourceLabel = this.state.name || this.state.key || this.state.id || 'DPU resource';
        const kindLabel = this.state.kind === 'secret' ? 'Secret' : 'Confidential';
        const ownerText = this.state.ownerId || 'Unknown';
        const roleText = this.state.role || 'none';
        this.summaryEl.innerHTML = `
            <div class="dpu-permissions-title">${resourceLabel}</div>
            <div class="dpu-permissions-meta">${kindLabel} · Path: ${this.state.path || '—'}</div>
            <div class="dpu-permissions-meta">Owner: ${ownerText} · Your role: ${roleText}</div>
        `;
    }

    renderStatus() {
        if (!this.statusEl) return;
        this.statusEl.textContent = this.state.status || '';
        this.statusEl.classList.toggle('error', this.state.statusType === 'error');
    }

    renderAcl() {
        if (!this.listEl) return;
        if (!Array.isArray(this.state.acl) || !this.state.acl.length) {
            this.listEl.innerHTML = `<div class="dpu-permissions-empty">No additional principals have access.</div>`;
            return;
        }
        const canManage = this.isOwner();
        const roleOptions = this.getRoleOptions();
        this.listEl.innerHTML = this.state.acl.map((entry) => `
            <div class="dpu-permissions-row">
                <div class="dpu-permissions-info">
                    <div class="dpu-permissions-principal">${escapeHtml(entry.principal)}</div>
                    ${canManage ? `
                        <label class="dpu-permissions-inline-editor">
                            <span>Role</span>
                            <select class="dpu-permissions-inline-role" ${this.state.busy ? 'disabled' : ''}>
                                ${roleOptions.map((role) => `
                                    <option value="${role}" ${role === entry.role ? 'selected' : ''}>${role}</option>
                                `).join('')}
                            </select>
                        </label>
                    ` : `
                        <div class="dpu-permissions-role">Role: ${escapeHtml(entry.role)}</div>
                    `}
                </div>
                ${canManage ? `
                    <div class="dpu-permissions-row-actions">
                        <button
                            type="button"
                            class="general-button secondary"
                            data-local-action="updatePermission ${entry.principal}"
                            ${this.state.busy ? 'disabled' : ''}
                        >
                            Update
                        </button>
                        <button
                            type="button"
                            class="gray-button"
                            data-local-action="revokePermission ${entry.principal}"
                            ${this.state.busy ? 'disabled' : ''}
                        >
                            Revoke
                        </button>
                    </div>
                ` : ''}
            </div>
        `).join('');
    }

    getBlockedPrincipalVariants() {
        const blocked = new Set();
        for (const value of [this.state.actorId, this.state.ownerId]) {
            for (const variant of normalizePrincipalVariants(value)) {
                blocked.add(variant);
            }
        }
        return blocked;
    }

    getAclRoleForPrincipal(principal = '') {
        const variants = normalizePrincipalVariants(principal);
        for (const entry of this.state.acl || []) {
            const entryVariants = normalizePrincipalVariants(entry.principal);
            if (entryVariants.some((value) => variants.includes(value))) {
                return String(entry.role || '').trim();
            }
        }
        return '';
    }

    getFilteredIdentities() {
        const blocked = this.getBlockedPrincipalVariants();
        const query = String(this.principalInput?.value || '').trim().toLowerCase();
        const identities = Array.isArray(this.state.identities) ? this.state.identities : [];
        return identities.filter((entry) => {
            const principal = String(entry.principal || '').trim();
            if (!principal || blocked.has(principal)) {
                return false;
            }
            const displayName = String(entry.name || '').trim().toLowerCase();
            const username = String(entry.username || '').trim().toLowerCase();
            const email = String(entry.email || '').trim().toLowerCase();
            if (!query) {
                return true;
            }
            return displayName.startsWith(query)
                || username.startsWith(query)
                || email.startsWith(query);
        }).slice(0, 8);
    }

    renderIdentitySuggestions() {
        if (!this.suggestionsEl) return;
        const filtered = this.getFilteredIdentities();
        const query = String(this.principalInput?.value || '').trim();
        if (!filtered.length) {
            this.suggestionsEl.innerHTML = query
                ? `<div class="dpu-permissions-picker-empty">No matching users. You can still grant access using a username or email.</div>`
                : '';
            this.suggestionsEl.classList.toggle('hidden', !this.state.pickerOpen || !query);
            return;
        }
        this.suggestionsEl.innerHTML = filtered.map((entry) => {
            const safePrincipal = escapeHtml(entry.principal);
            const safeName = escapeHtml(entry.name || entry.username || entry.principal);
            const aclRole = this.getAclRoleForPrincipal(entry.principal);
            const metaParts = [
                entry.email || entry.username || entry.principal
            ];
            if (aclRole) {
                metaParts.push(`Current access: ${aclRole}`);
            }
            const safeMeta = escapeHtml(metaParts.filter(Boolean).join(' · '));
            return `
                <button
                    type="button"
                    class="dpu-permissions-suggestion"
                    data-local-action="selectSuggestedPrincipal ${safePrincipal}"
                    role="option"
                >
                    <div class="dpu-permissions-suggestion-name">${safeName}</div>
                    <div class="dpu-permissions-suggestion-meta">${safeMeta}</div>
                </button>
            `;
        }).join('');
        this.suggestionsEl.classList.toggle('hidden', !this.state.pickerOpen);
    }

    hideIdentitySuggestions() {
        if (!this.suggestionsEl) return;
        this.state.pickerOpen = false;
        this.suggestionsEl.classList.add('hidden');
    }

    async loadIdentities() {
        const users = await fetchLocalUsers(this.state.agent);
        this.state.identities = users.map((entry) => {
            const username = String(entry.username || '').trim();
            const email = String(entry.email || '').trim();
            return {
                id: String(entry.id || '').trim(),
                principal: username || email,
                username,
                email,
                name: String(entry.name || username || email || '').trim()
            };
        }).filter((entry) => isNonEmptyString(entry.principal));
        if (this.principalInput) {
            this.principalInput.placeholder = this.state.identities.length
                ? 'Search user by name or username'
                : 'Type a username or email';
        }
    }

    updateFormState() {
        const canManage = this.isOwner();
        const disabled = !canManage || this.state.busy;
        if (this.grantSectionEl) {
            this.grantSectionEl.hidden = !canManage;
        }
        if (this.principalInput) this.principalInput.disabled = disabled;
        if (this.suggestionsEl) this.suggestionsEl.classList.toggle('hidden', disabled || !this.state.pickerOpen || this.suggestionsEl.innerHTML === '');
        if (this.roleSelect) this.roleSelect.disabled = disabled;
        this.element.querySelectorAll('.dpu-permissions-inline-role').forEach((select) => {
            select.disabled = this.state.busy || !canManage;
        });
        this.element.querySelectorAll('[data-local-action^="updatePermission"]').forEach((button) => {
            button.disabled = this.state.busy || !canManage;
        });
        this.element.querySelectorAll('[data-local-action^="revokePermission"]').forEach((button) => {
            button.disabled = this.state.busy || !canManage;
        });
        const actionButtons = this.element.querySelectorAll('[data-local-action="grantPermission"]');
        actionButtons.forEach((button) => {
            button.disabled = disabled;
        });
        if (!canManage) {
            this.setStatus(
                this.state.role === 'write'
                    ? 'You can view current access because you have write, but only the owner can change permissions.'
                    : 'Only the owner can grant or revoke permissions.',
                ''
            );
        }
    }

    async loadData() {
        this.state.busy = true;
        this.setStatus('Loading permissions...', '');
        try {
            const whoami = await callDpuTool('dpu_whoami');
            this.state.actorId = String(whoami?.actor?.principalId || '').trim();
            await this.loadIdentities();

            if (this.state.kind === 'secret') {
                const result = await callDpuTool('dpu_secret_get', { key: this.state.key });
                const secret = result.secret || {};
                this.state.ownerId = String(secret.ownerId || '').trim();
                this.state.role = String(secret.role || '').trim();
                this.state.acl = Array.isArray(secret.acl) ? secret.acl : [];
                this.state.name = this.state.key || this.state.name;
            } else {
                const result = await callDpuTool('dpu_confidential_get', { id: this.state.id });
                const objectRecord = result.object || {};
                this.state.ownerId = String(objectRecord.ownerId || '').trim();
                this.state.role = String(objectRecord.role || '').trim();
                this.state.acl = Array.isArray(objectRecord.acl) ? objectRecord.acl : [];
                this.state.name = objectRecord.name || this.state.name;
            }

            this.renderSummary();
            this.renderAcl();
            this.renderIdentitySuggestions();
            this.state.status = '';
            this.state.statusType = '';
        } catch (error) {
            this.setStatus(error?.message || 'Failed to load permissions.', 'error');
        } finally {
            this.state.busy = false;
            this.renderAcl();
            this.updateFormState();
            this.renderStatus();
        }
    }

    async grantPermission() {
        const principal = String(this.selectedPrincipal || this.principalInput?.value || '').trim();
        const role = String(this.roleSelect?.value || '').trim();
        if (!principal || !role) {
            this.setStatus('User and role are required.', 'error');
            return;
        }
        this.state.busy = true;
        this.updateFormState();
        this.setStatus('Granting permission...', '');
        try {
            if (this.state.kind === 'secret') {
                await callDpuTool('dpu_secret_grant', {
                    key: this.state.key,
                    principal,
                    role
                });
            } else {
                await callDpuTool('dpu_confidential_grant', {
                    id: this.state.id,
                    principal,
                    role
                });
            }
            this.state.changed = true;
            if (this.principalInput) {
                this.principalInput.value = '';
            }
            this.selectedPrincipal = '';
            this.hideIdentitySuggestions();
            await this.loadData();
            this.setStatus(`Granted ${role} to ${principal}.`, '');
        } catch (error) {
            this.state.busy = false;
            this.updateFormState();
            this.setStatus(error?.message || 'Failed to grant permission.', 'error');
        }
    }

    selectSuggestedPrincipal(_target, principal) {
        const normalizedPrincipal = String(principal || '').trim();
        if (!normalizedPrincipal || !this.principalInput) {
            return;
        }
        this.selectedPrincipal = normalizedPrincipal;
        const matched = (this.state.identities || []).find((entry) => entry.principal === normalizedPrincipal) || null;
        this.principalInput.value = matched?.username || matched?.email || normalizedPrincipal;
        this.hideIdentitySuggestions();
    }

    async revokePermission(_target, principal) {
        const normalizedPrincipal = String(principal || '').trim();
        if (!normalizedPrincipal) return;
        this.state.busy = true;
        this.updateFormState();
        this.setStatus(`Revoking ${normalizedPrincipal}...`, '');
        try {
            if (this.state.kind === 'secret') {
                await callDpuTool('dpu_secret_revoke', {
                    key: this.state.key,
                    principal: normalizedPrincipal
                });
            } else {
                await callDpuTool('dpu_confidential_revoke', {
                    id: this.state.id,
                    principal: normalizedPrincipal
                });
            }
            this.state.changed = true;
            await this.loadData();
            this.setStatus(`Revoked access from ${normalizedPrincipal}.`, '');
        } catch (error) {
            this.state.busy = false;
            this.updateFormState();
            this.setStatus(error?.message || 'Failed to revoke permission.', 'error');
        }
    }

    async updatePermission(target, principal) {
        const normalizedPrincipal = String(principal || '').trim();
        const row = target?.closest?.('.dpu-permissions-row') || null;
        const inlineRole = row?.querySelector?.('.dpu-permissions-inline-role');
        const nextRole = String(inlineRole?.value || '').trim();
        if (!normalizedPrincipal || !nextRole) {
            this.setStatus('User and role are required.', 'error');
            return;
        }
        const currentRole = this.getAclRoleForPrincipal(normalizedPrincipal);
        if (currentRole === nextRole) {
            this.setStatus(`No change needed for ${normalizedPrincipal}.`, '');
            return;
        }
        this.state.busy = true;
        this.updateFormState();
        this.setStatus(`Updating ${normalizedPrincipal}...`, '');
        try {
            if (this.state.kind === 'secret') {
                await callDpuTool('dpu_secret_grant', {
                    key: this.state.key,
                    principal: normalizedPrincipal,
                    role: nextRole
                });
            } else {
                await callDpuTool('dpu_confidential_grant', {
                    id: this.state.id,
                    principal: normalizedPrincipal,
                    role: nextRole
                });
            }
            this.state.changed = true;
            await this.loadData();
            this.setStatus(`Updated ${normalizedPrincipal} to ${nextRole}.`, '');
        } catch (error) {
            this.state.busy = false;
            this.updateFormState();
            this.setStatus(error?.message || 'Failed to update permission.', 'error');
        }
    }

    closeModal() {
        assistOS.UI.closeModal(this.element, { changed: this.state.changed });
    }
}
