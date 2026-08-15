/* ==========================================================================
   Kestrel Documentation — Main JavaScript
   Handles: theme toggle, sidebar nav, search, TOC, code copy, mobile menu
   Vanilla JS, no dependencies. Modern ES2020+.
   ========================================================================== */

(function () {
  'use strict';

  // ─── Documentation search index ──────────────────────────
  // 每项: { title, section, id, keywords }
  const SEARCH_INDEX = [
    { title: 'Kestrel 概述', section: '概述', id: 'overview', keywords: 'kestrel 概述 容器 安全 遥测 归一化' },
    { title: '架构设计', section: '架构', id: 'architecture', keywords: '架构 stdin stdout main sidecar service detectSource k8s docker' },
    { title: '检测管线', section: '架构', id: 'pipeline', keywords: '检测管线 raw telemetry sidecar signal activity context risk finding mitre' },
    { title: '项目结构', section: '快速开始', id: 'project-structure', keywords: '项目结构 main.go internal model service config utilities k8s test' },
    { title: '快速开始', section: '快速开始', id: 'quick-start', keywords: '快速开始 make build demo test vet lint' },
    { title: '命令行配置', section: '配置', id: 'config', keywords: '配置 cluster-id verbose log-format 环境变量 KESTREL_CLUSTER_ID' },
    { title: '使用方式', section: '使用', id: 'usage', keywords: '使用方式 文件 流处理 docker events kubectl 实时 verbose' },
    { title: 'Kubernetes 部署', section: '部署', id: 'k8s-deploy', keywords: 'kubernetes 部署 kustomize namespace configmap rbac deployment service ingress' },
    { title: '安全配置基线', section: '部署', id: 'security-context', keywords: '安全 runAsNonRoot readOnlyRootFilesystem allowPrivilegeEscalation capabilities seccomp' },
    { title: '遥测来源 - K8s 审计', section: '遥测', id: 'telemetry-k8s', keywords: 'k8s 审计 audit container exec attach portforward requestURI subresource' },
    { title: '遥测来源 - Docker 事件', section: '遥测', id: 'telemetry-docker', keywords: 'docker 事件 exec_create exec_start attach actor container image' },
    { title: '身份分类', section: '归一化', id: 'identity', keywords: '身份 anonymous service_account node user system:anonymous' },
    { title: '命令提取', section: '归一化', id: 'command-extract', keywords: '命令 提取 requestURI 查询参数 url decode /bin/sh' },
    { title: '被拒绝的 exec', section: '归一化', id: 'denied-exec', keywords: 'denied 403 401 拒绝 forbidden metadata denied true' },
    { title: '输出示例', section: '使用', id: 'output-example', keywords: '输出 示例 json auditID actor action target source metadata' },
    { title: '一键全场景模拟 (make simulate)', section: '测试', id: 'simulate', keywords: 'simulate 模拟 测试 自动化 6 阶段 表格 报告' },
    { title: '单元测试', section: '测试', id: 'unit-tests', keywords: '单元测试 sidecar_test go test 12 用例' },
    { title: 'exec 攻击测试方法论', section: '测试', id: 'exec-attack', keywords: 'exec 攻击 方法论 20 场景 质量门禁 报告' },
    { title: 'e2e 真实场景测试', section: '测试', id: 'e2e', keywords: 'e2e 真实 minikube kubectl exec 审计日志' },
    { title: '集成安全测试', section: '测试', id: 'integration', keywords: '集成 安全 测试 12 类 攻击 路径穿越 命令注入 ssrf xss' },
    { title: '设计原则', section: '设计', id: 'principles', keywords: '设计原则 归一化 检测 denied docker 保守 零依赖 管道 优雅关停' },
    { title: 'MITRE ATT&CK 映射', section: '设计', id: 'mitre', keywords: 'mitre attack t1059.013 container cli api det0083 an0233' }
  ];

  // ─── 主题切换 ────────────────────────────────────────────
  const THEME_KEY = 'kestrel-doc-theme';
  const root = document.documentElement;

  function getStoredTheme() {
    return localStorage.getItem(THEME_KEY);
  }

  function getPreferredTheme() {
    const stored = getStoredTheme();
    if (stored) return stored;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function applyTheme(theme) {
    root.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
    updateThemeToggle(theme);
  }

  function updateThemeToggle(theme) {
    const toggle = document.querySelector('.theme-toggle');
    if (!toggle) return;
    toggle.setAttribute('aria-label', theme === 'dark' ? '切换到亮色主题' : '切换到暗色主题');
  }

  function initTheme() {
    applyTheme(getPreferredTheme());
    const toggle = document.querySelector('.theme-toggle');
    if (toggle) {
      toggle.addEventListener('click', function () {
        const current = root.getAttribute('data-theme');
        applyTheme(current === 'dark' ? 'light' : 'dark');
      });
    }
  }

  // ─── 侧边栏导航 (active link) ────────────────────────────
  function initSidebarActive() {
    const links = Array.from(document.querySelectorAll('.sidebar-link'));
    if (!links.length) return;

    const sectionsById = new Map();
    links.forEach(function (link) {
      const id = link.getAttribute('href');
      if (id && id.startsWith('#')) {
        const section = document.querySelector(id);
        if (section) sectionsById.set(id.slice(1), { link: link, section: section });
      }
    });

    if (!('IntersectionObserver' in window) || sectionsById.size === 0) return;

    const observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        const id = entry.target.id;
        const item = sectionsById.get(id);
        if (!item) return;
        if (entry.isIntersecting) {
          links.forEach(function (l) { l.classList.remove('active'); });
          item.link.classList.add('active');
          updateBreadcrumb(entry.target);
        }
      });
    }, {
      rootMargin: '-' + Math.round(parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--header-height'))) + 'px 0px -70% 0px',
      threshold: 0
    });

    sectionsById.forEach(function (item) { observer.observe(item.section); });
  }

  // ─── 面包屑 ──────────────────────────────────────────────
  function updateBreadcrumb(section) {
    const bc = document.querySelector('[data-breadcrumb]');
    if (!bc) return;
    const id = section.id;
    const title = section.querySelector('h2, h1');
    const titleText = title ? title.textContent : id;
    bc.innerHTML =
      '<span class="breadcrumb-item"><a href="#overview">首页</a></span>' +
      '<span class="breadcrumb-sep">/</span>' +
      '<span class="breadcrumb-item"><a href="#' + id + '">' + (section.dataset.section || '文档') + '</a></span>' +
      '<span class="breadcrumb-sep">/</span>' +
      '<span class="breadcrumb-current">' + escapeHtml(titleText) + '</span>';
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // ─── 目录 (Table of Contents) ────────────────────────────
  function initToc() {
    const toc = document.querySelector('[data-toc]');
    if (!toc) return;
    const headings = Array.from(document.querySelectorAll('.main h2, .main h3'));
    if (headings.length === 0) { toc.style.display = 'none'; return; }

    const list = toc.querySelector('.toc-list') || toc;
    list.innerHTML = '';

    headings.forEach(function (h) {
      if (!h.id) {
        h.id = h.textContent.trim().toLowerCase().replace(/[^\w\u4e00-\u9fa5]+/g, '-').replace(/^-|-$/g, '');
      }
      const link = document.createElement('a');
      link.href = '#' + h.id;
      link.className = 'toc-link' + (h.tagName === 'H3' ? ' sub' : '');
      link.textContent = h.textContent;
      link.setAttribute('data-toc-target', h.id);
      list.appendChild(link);
    });

    if (!('IntersectionObserver' in window)) return;
    const tocLinks = Array.from(toc.querySelectorAll('.toc-link'));
    const observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        const id = entry.target.id;
        const link = toc.querySelector('[data-toc-target="' + CSS.escape(id) + '"]');
        if (!link) return;
        if (entry.isIntersecting) {
          tocLinks.forEach(function (l) { l.classList.remove('active'); });
          link.classList.add('active');
        }
      });
    }, { rootMargin: '-80px 0px -70% 0px', threshold: 0 });

    headings.forEach(function (h) { observer.observe(h); });
  }

  // ─── 搜索 (Command palette) ──────────────────────────────
  function initSearch() {
    const trigger = document.querySelector('.search-trigger');
    const modal = document.querySelector('.search-modal');
    if (!modal) return;
    const input = modal.querySelector('.search-input');
    const results = modal.querySelector('.search-results');
    const footer = modal.querySelector('.search-footer-count');

    function open() {
      modal.classList.add('open');
      setTimeout(function () { input.focus(); }, 50);
      document.body.style.overflow = 'hidden';
    }

    function close() {
      modal.classList.remove('open');
      input.value = '';
      results.innerHTML = '';
      document.body.style.overflow = '';
      if (footer) footer.textContent = SEARCH_INDEX.length;
    }

    if (trigger) trigger.addEventListener('click', open);

    modal.addEventListener('click', function (e) {
      if (e.target === modal) close();
    });

    document.addEventListener('keydown', function (e) {
      // Cmd/Ctrl+K 打开
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        if (modal.classList.contains('open')) close(); else open();
      }
      // ESC 关闭
      if (e.key === 'Escape' && modal.classList.contains('open')) {
        close();
      }
    });

    let selectedIdx = -1;
    let currentResults = [];

    function fuzzyMatch(query, text) {
      query = query.toLowerCase();
      text = text.toLowerCase();
      if (!query) return 0;
      let qi = 0, score = 0, streak = 0;
      for (let i = 0; i < text.length && qi < query.length; i++) {
        if (text[i] === query[qi]) {
          qi++;
          streak++;
          score += 1 + streak;
        } else {
          streak = 0;
        }
      }
      return qi === query.length ? score : 0;
    }

    function highlight(text, query) {
      if (!query) return escapeHtml(text);
      const lower = text.toLowerCase();
      const q = query.toLowerCase();
      let out = '', i = 0;
      while (i < text.length) {
        const idx = lower.indexOf(q, i);
        if (idx === -1) { out += escapeHtml(text.slice(i)); break; }
        out += escapeHtml(text.slice(i, idx));
        out += '<mark>' + escapeHtml(text.slice(idx, idx + q.length)) + '</mark>';
        i = idx + q.length;
      }
      return out;
    }

    input.addEventListener('input', function () {
      const q = input.value.trim();
      currentResults = [];
      selectedIdx = -1;

      if (!q) {
        results.innerHTML = '<div class="search-empty">输入关键词搜索文档</div>';
        if (footer) footer.textContent = SEARCH_INDEX.length;
        return;
      }

      const scored = SEARCH_INDEX.map(function (item) {
        const s1 = fuzzyMatch(q, item.title) * 3;
        const s2 = fuzzyMatch(q, item.section);
        const s3 = fuzzyMatch(q, item.keywords) * 0.5;
        return { item: item, score: s1 + s2 + s3 };
      }).filter(function (x) { return x.score > 0; })
        .sort(function (a, b) { return b.score - a.score; });

      currentResults = scored.map(function (x) { return x.item; });

      if (currentResults.length === 0) {
        results.innerHTML = '<div class="search-empty">未找到匹配的文档</div>';
        if (footer) footer.textContent = '0';
        return;
      }

      results.innerHTML = currentResults.slice(0, 12).map(function (item, i) {
        return '<a class="search-result' + (i === 0 ? ' selected' : '') + '" href="#' + item.id + '" data-idx="' + i + '">' +
          '<div class="search-result-title">' + highlight(item.title, q) + '</div>' +
          '<div class="search-result-path">' + escapeHtml(item.section) + ' / #' + item.id + '</div>' +
          '</a>';
      }).join('');

      if (footer) footer.textContent = currentResults.length;
      selectedIdx = 0;
    });

    results.addEventListener('click', function (e) {
      const target = e.target.closest('.search-result');
      if (!target) return;
      const href = target.getAttribute('href');
      if (href) {
        close();
        const el = document.querySelector(href);
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });

    input.addEventListener('keydown', function (e) {
      const items = results.querySelectorAll('.search-result');
      if (items.length === 0) return;

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        selectedIdx = (selectedIdx + 1) % items.length;
        updateSelected(items);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        selectedIdx = (selectedIdx - 1 + items.length) % items.length;
        updateSelected(items);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (selectedIdx >= 0 && items[selectedIdx]) items[selectedIdx].click();
      }
    });

    function updateSelected(items) {
      items.forEach(function (el, i) {
        el.classList.toggle('selected', i === selectedIdx);
        if (i === selectedIdx) el.scrollIntoView({ block: 'nearest' });
      });
    }

    if (footer) footer.textContent = SEARCH_INDEX.length;
  }

  // ─── 代码块复制 ──────────────────────────────────────────
  function initCodeCopy() {
    document.querySelectorAll('.code-copy').forEach(function (btn) {
      btn.addEventListener('click', function () {
        const block = btn.closest('.code-block');
        if (!block) return;
        const code = block.querySelector('code');
        if (!code) return;
        const text = code.textContent;

        if (navigator.clipboard) {
          navigator.clipboard.writeText(text).then(function () {
            flashCopy(btn);
          });
        } else {
          const ta = document.createElement('textarea');
          ta.value = text;
          document.body.appendChild(ta);
          ta.select();
          try { document.execCommand('copy'); flashCopy(btn); } catch (_) {}
          document.body.removeChild(ta);
        }
      });
    });
  }

  function flashCopy(btn) {
    const original = btn.innerHTML;
    btn.innerHTML = '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 4L6 11L3 8"/></svg>';
    btn.style.color = 'var(--color-success)';
    setTimeout(function () {
      btn.innerHTML = original;
      btn.style.color = '';
    }, 1500);
  }

  // ─── 移动端菜单 ──────────────────────────────────────────
  function initMobileMenu() {
    const btn = document.querySelector('.mobile-menu-btn');
    const sidebar = document.querySelector('.sidebar');
    const backdrop = document.querySelector('.sidebar-backdrop');
    if (!btn || !sidebar) return;

    function toggle() {
      const open = sidebar.classList.toggle('open');
      if (backdrop) backdrop.classList.toggle('open', open);
      btn.setAttribute('aria-expanded', open);
      document.body.style.overflow = open ? 'hidden' : '';
    }

    btn.addEventListener('click', toggle);
    if (backdrop) backdrop.addEventListener('click', toggle);

    // 点击导航链接后自动关闭
    sidebar.addEventListener('click', function (e) {
      if (e.target.classList.contains('sidebar-link') && window.innerWidth <= 768) {
        sidebar.classList.remove('open');
        if (backdrop) backdrop.classList.remove('open');
        document.body.style.overflow = '';
      }
    });
  }

  // ─── 平滑滚动 ─────────────────────────────────────────────
  function initSmoothScroll() {
    document.addEventListener('click', function (e) {
      const link = e.target.closest('a[href^="#"]');
      if (!link) return;
      const href = link.getAttribute('href');
      if (href === '#' || href === '#overview' && window.scrollY === 0) return;
      const target = document.querySelector(href);
      if (!target) return;
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      history.replaceState(null, '', href);
    });
  }

  // ─── 滚动到顶部按钮 ──────────────────────────────────────
  function initScrollTop() {
    const btn = document.querySelector('.scroll-top');
    if (!btn) return;
    window.addEventListener('scroll', function () {
      btn.classList.toggle('visible', window.scrollY > 800);
    }, { passive: true });
    btn.addEventListener('click', function () {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  // ─── 初始化 ──────────────────────────────────────────────
  function init() {
    initTheme();
    initSidebarActive();
    initToc();
    initSearch();
    initCodeCopy();
    initMobileMenu();
    initSmoothScroll();
    initScrollTop();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
