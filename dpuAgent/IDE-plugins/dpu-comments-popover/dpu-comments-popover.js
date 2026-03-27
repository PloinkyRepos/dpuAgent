function escapeHtml(value) {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

function formatCommentDate(value) {
    if (!value) return '';
    try {
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return String(value);
        }
        return date.toLocaleString();
    } catch (_) {
        return String(value);
    }
}

function toBool(value) {
    return value === true || value === 'true';
}

function cloneComments(input) {
    return Array.isArray(input) ? input.map((entry) => ({ ...entry })) : [];
}

export class DpuCommentsPopover {
    constructor(element, invalidate) {
        this.element = element;
        this.invalidate = invalidate;
        this.state = {
            objectId: '',
            path: '',
            open: false,
            canComment: false,
            comments: [],
            busy: false,
            draft: '',
            error: ''
        };
        this.invalidate();
    }

    updateHostContext(context = {}) {
        this.state = {
            ...this.state,
            objectId: String(context.objectId || ''),
            path: String(context.path || ''),
            open: toBool(context.open),
            canComment: Boolean(context.canComment),
            comments: cloneComments(context.comments),
            error: ''
        };
        this.toggleHidden();
        this.invalidate();
    }

    toggleHidden() {
        this.element.toggleAttribute('hidden', !this.state.open);
    }

    async beforeRender() {
        this.toggleHidden();
        this.title = this.state.comments.length > 0 ? `Comments (${this.state.comments.length})` : 'Comments';
        this.subtitle = this.state.canComment
            ? 'Annotations for this confidential file.'
            : 'Read-only annotations for this confidential file.';
        this.commentsHtml = this.renderComments();
        this.composerHtml = this.renderComposer();
    }

    afterRender() {
        this.toggleHidden();
        const textarea = this.element.querySelector('.composer-textarea');
        const submitButton = this.element.querySelector('[data-local-action="submitComment"]');
        if (textarea) {
            textarea.value = this.state.draft || '';
            textarea.addEventListener('input', (event) => {
                this.updateDraft(event.target, submitButton);
            });
        }
        this.syncComposerState(submitButton);
    }

    renderComments() {
        if (!this.state.comments.length) {
            return `<div class="empty">No comments yet.</div>`;
        }
        const rows = this.state.comments.map((comment) => `
            <article class="comment-row">
                <div class="comment-meta">
                    <div class="comment-author-row">
                        <span class="comment-avatar" aria-hidden="true">${escapeHtml((comment.userEmail || comment.authorPrincipal || 'U').slice(0, 1).toUpperCase())}</span>
                        <span class="comment-author">${escapeHtml(comment.userEmail || comment.authorPrincipal || 'Unknown')}</span>
                    </div>
                    <time class="comment-date" datetime="${escapeHtml(comment.createdAt || '')}">${escapeHtml(formatCommentDate(comment.createdAt || ''))}</time>
                </div>
                <div class="comment-message">${escapeHtml(comment.message || '')}</div>
                ${comment.canDelete ? `
                    <div class="comment-actions">
                        <button type="button" class="general-button secondary" data-local-action="deleteComment ${escapeHtml(comment.id || '')}">
                            Delete
                        </button>
                    </div>
                ` : ''}
            </article>
        `).join('');
        return `<div class="comments-list">${rows}</div>`;
    }

    renderComposer() {
        if (!this.state.canComment) {
            return '';
        }
        const disabledClass = !String(this.state.draft || '').trim() || this.state.busy ? ' disabled' : '';
        const disabledAttr = disabledClass ? ' disabled' : '';
        const errorHtml = this.state.error
            ? `<div class="empty">${escapeHtml(this.state.error)}</div>`
            : '';
        return `
            <div class="composer">
                <label class="composer-label" for="dpu-comment-draft">Add comment</label>
                <textarea id="dpu-comment-draft" class="composer-textarea" placeholder="Add your comment..."></textarea>
                ${errorHtml}
                <div class="composer-actions">
                    <button type="button" class="general-button${disabledClass}" data-local-action="submitComment"${disabledAttr}>
                        ${this.state.busy ? 'Saving...' : 'Add comment'}
                    </button>
                </div>
            </div>
        `;
    }

    updateDraft(target, submitButton) {
        this.state.draft = target?.value || '';
        this.syncComposerState(submitButton);
    }

    syncComposerState(submitButton = this.element.querySelector('[data-local-action="submitComment"]')) {
        if (!submitButton) {
            return;
        }
        const disabled = !String(this.state.draft || '').trim() || this.state.busy;
        submitButton.disabled = disabled;
        submitButton.classList.toggle('disabled', disabled);
    }

    closePopover() {
        this.element.dispatchEvent(new CustomEvent('dpu-comments-close', {
            bubbles: true
        }));
    }

    async submitComment() {
        const message = String(this.state.draft || '').trim();
        if (!message || !this.state.objectId || this.state.busy) {
            return;
        }
        this.state.busy = true;
        this.state.error = '';
        this.invalidate();
        try {
            await window.assistOS?.appServices?.callTool?.('dpuAgent', 'dpu_confidential_comment_add', {
                id: this.state.objectId,
                message
            });
            this.state.draft = '';
            await this.refreshComments();
        } catch (error) {
            this.state.error = error?.message || 'Failed to add comment.';
        } finally {
            this.state.busy = false;
            this.invalidate();
        }
    }

    async deleteComment(_target, commentId) {
        if (!this.state.objectId || !commentId || this.state.busy) {
            return;
        }
        this.state.busy = true;
        this.state.error = '';
        this.invalidate();
        try {
            await window.assistOS?.appServices?.callTool?.('dpuAgent', 'dpu_confidential_comment_delete', {
                id: this.state.objectId,
                commentId: String(commentId)
            });
            await this.refreshComments();
        } catch (error) {
            this.state.error = error?.message || 'Failed to delete comment.';
        } finally {
            this.state.busy = false;
            this.invalidate();
        }
    }

    async refreshComments() {
        const result = await window.assistOS?.appServices?.callTool?.('dpuAgent', 'dpu_confidential_get', {
            id: this.state.objectId
        });
        const objectRecord = result?.json?.object || result?.object || {};
        this.state.comments = cloneComments(objectRecord.comments);
        this.state.canComment = Boolean(objectRecord.canComment);
        this.emitCommentsChanged();
    }

    emitCommentsChanged() {
        this.element.dispatchEvent(new CustomEvent('dpu-comments-state', {
            bubbles: true,
            detail: {
                objectId: this.state.objectId,
                commentCount: this.state.comments.length,
                comments: cloneComments(this.state.comments),
                canComment: this.state.canComment
            }
        }));
    }
}
