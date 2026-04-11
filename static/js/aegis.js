/* ==========================================================================
   AEGIS v7.0 — Shared JavaScript
   Sidebar toggle, toast system, keyboard shortcuts, theme utils
   ========================================================================== */

const Aegis = (() => {
  'use strict';

  // ---------- Sidebar ----------
  function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const appMain = document.getElementById('appMain');
    const topbar = document.getElementById('topbar');
    const footer = document.getElementById('statusFooter');
    const toggleBtn = document.getElementById('sidebarToggle');
    const mobileToggle = document.getElementById('mobileMenuToggle');

    if (!sidebar) return;

    const saved = localStorage.getItem('aegis-sidebar-collapsed');
    if (saved === 'true') {
      sidebar.classList.add('collapsed');
      if (appMain) appMain.classList.add('sidebar-collapsed');
      if (topbar) topbar.classList.add('sidebar-collapsed');
      if (footer) footer.classList.add('sidebar-collapsed');
    }

    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        const isCollapsed = sidebar.classList.toggle('collapsed');
        if (appMain) appMain.classList.toggle('sidebar-collapsed');
        if (topbar) topbar.classList.toggle('sidebar-collapsed');
        if (footer) footer.classList.toggle('sidebar-collapsed');
        localStorage.setItem('aegis-sidebar-collapsed', isCollapsed);
        
        const icon = toggleBtn.querySelector('i');
        if (icon) {
          icon.className = isCollapsed ? 'fas fa-angles-right' : 'fas fa-angles-left';
        }
      });
    }

    if (mobileToggle) {
      mobileToggle.addEventListener('click', () => {
        sidebar.classList.toggle('mobile-open');
      });
    }

    // Close mobile sidebar on click outside
    document.addEventListener('click', (e) => {
      if (window.innerWidth <= 1024 && sidebar.classList.contains('mobile-open')) {
        if (!sidebar.contains(e.target) && (!mobileToggle || !mobileToggle.contains(e.target))) {
          sidebar.classList.remove('mobile-open');
        }
      }
    });
  }

  // ---------- Toast Notifications ----------
  let toastContainer = null;

  function initToasts() {
    if (!document.getElementById('toastContainer')) {
      toastContainer = document.createElement('div');
      toastContainer.id = 'toastContainer';
      toastContainer.className = 'toast-container';
      document.body.appendChild(toastContainer);
    } else {
      toastContainer = document.getElementById('toastContainer');
    }
  }

  function toast(message, type = 'info', duration = 4000) {
    if (!toastContainer) initToasts();

    const icons = {
      info: 'fa-circle-info',
      success: 'fa-circle-check',
      warning: 'fa-triangle-exclamation',
      error: 'fa-circle-xmark'
    };

    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.innerHTML = `
      <i class="fas ${icons[type] || icons.info}" style="font-size:1.1rem"></i>
      <span style="flex:1;font-size:0.85rem">${message}</span>
      <button onclick="this.parentElement.remove()" style="background:none;border:none;color:var(--text-muted);cursor:pointer;padding:0.25rem">
        <i class="fas fa-xmark"></i>
      </button>
    `;

    toastContainer.appendChild(el);

    if (duration > 0) {
      setTimeout(() => {
        el.style.opacity = '0';
        el.style.transform = 'translateX(100%)';
        el.style.transition = 'all 0.3s ease';
        setTimeout(() => el.remove(), 300);
      }, duration);
    }

    return el;
  }

  // ---------- Keyboard Shortcuts ----------
  function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      // Ctrl+K or Cmd+K → Focus search
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = document.getElementById('globalSearch');
        if (searchInput) searchInput.focus();
      }

      // Escape → Close modals and mobile sidebar
      if (e.key === 'Escape') {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) sidebar.classList.remove('mobile-open');
        
        // Close any open modals
        document.querySelectorAll('.modal-overlay.active').forEach(m => {
          m.classList.remove('active');
        });
      }

      // Ctrl+N → New scan
      if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
        e.preventDefault();
        window.location.href = '/scan/new';
      }
    });
  }

  // ---------- Active Nav Highlight ----------
  function highlightActiveNav() {
    const path = window.location.pathname;
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.remove('active');
      const href = item.getAttribute('href');
      if (href === path || (href !== '/' && path.startsWith(href))) {
        item.classList.add('active');
      }
    });
  }

  // ---------- Tabs ----------
  function initTabs() {
    document.querySelectorAll('[data-tab-group]').forEach(group => {
      const groupName = group.dataset.tabGroup;
      const buttons = group.querySelectorAll('.tab-btn');
      
      buttons.forEach(btn => {
        btn.addEventListener('click', () => {
          const target = btn.dataset.tab;
          
          // Deactivate all buttons and content in group
          buttons.forEach(b => b.classList.remove('active'));
          document.querySelectorAll(`[data-tab-content="${groupName}"]`).forEach(c => {
            c.classList.remove('active');
          });
          
          // Activate clicked
          btn.classList.add('active');
          const content = document.getElementById(target);
          if (content) content.classList.add('active');
        });
      });
    });
  }

  // ---------- Global Search ----------
  function initGlobalSearch() {
    const searchInput = document.getElementById('globalSearch');
    if (!searchInput) return;

    let debounceTimer;
    searchInput.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        const query = searchInput.value.trim();
        if (query.length >= 2) {
          // Could implement global search here
          console.log('Search:', query);
        }
      }, 300);
    });

    searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const query = searchInput.value.trim();
        if (query) {
          // Navigate to scan with URL if it looks like a domain/URL
          const isDomain = /^[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}/.test(query);
          if (isDomain) {
            window.location.href = '/scan/new?target=' + encodeURIComponent(query);
          }
        }
      }
    });
  }

  // ---------- Utilities ----------
  function formatNumber(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return n.toString();
  }

  function timeAgo(dateStr) {
    const date = new Date(dateStr);
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);
    
    const intervals = [
      { label: 'y', seconds: 31536000 },
      { label: 'mo', seconds: 2592000 },
      { label: 'd', seconds: 86400 },
      { label: 'h', seconds: 3600 },
      { label: 'm', seconds: 60 },
    ];
    
    for (const interval of intervals) {
      const count = Math.floor(seconds / interval.seconds);
      if (count > 0) return `${count}${interval.label} ago`;
    }
    return 'just now';
  }

  function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
      toast('Copied to clipboard', 'success', 2000);
    }).catch(() => {
      toast('Failed to copy', 'error');
    });
  }

  function severityColor(level) {
    const map = {
      critical: 'var(--sev-critical)',
      high: 'var(--sev-high)',
      medium: 'var(--sev-medium)',
      low: 'var(--sev-low)',
      info: 'var(--sev-info)',
      ok: 'var(--sev-ok)',
    };
    return map[level] || map.info;
  }

  function severityBadge(level) {
    return `<span class="badge badge-${level}">${level.toUpperCase()}</span>`;
  }

  // ---------- Init ----------
  function init() {
    initSidebar();
    initToasts();
    initKeyboardShortcuts();
    highlightActiveNav();
    initTabs();
    initGlobalSearch();
  }

  // Auto-init on DOMContentLoaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Public API
  return {
    toast,
    formatNumber,
    timeAgo,
    copyToClipboard,
    severityColor,
    severityBadge,
    initTabs,
  };
})();
