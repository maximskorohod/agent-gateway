// Минимальный скрипт сайта: кнопка «Скопировать» (data-copy), подсветка раздела в шапке
// и автофокус поля кода. Других задач у скрипта нет; инлайн-скриптов в разметке нет (CSP без unsafe-inline).
(function () {
  'use strict';

  function selectText(node) {
    try {
      const range = document.createRange();
      range.selectNodeContents(node);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    } catch (e) {
      // Выделение недоступно — пользователь скопирует вручную.
    }
  }

  function copyFrom(button) {
    const source = document.querySelector(button.getAttribute('data-copy') || '');
    if (!source) return;
    const label = button.textContent;
    const show = (text) => {
      button.textContent = text;
      setTimeout(() => { button.textContent = label; }, 2000);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(source.textContent || '').then(
        () => show(button.getAttribute('data-copied') || 'Copied'),
        () => { selectText(source); show(button.getAttribute('data-selected') || 'Press Ctrl+C'); }
      );
    } else {
      selectText(source);
      show(button.getAttribute('data-selected') || 'Press Ctrl+C');
    }
  }

  // Резервные коды: «Дальше» доступна после скачивания или копирования. Без JS кнопка просто активна.
  const afterSave = document.querySelector('[data-after-save]');
  if (afterSave) afterSave.disabled = true;

  document.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null;
    const button = target ? target.closest('[data-copy]') : null;
    if (button) copyFrom(button);
    if (afterSave && target && target.closest('[data-saves-codes]')) {
      afterSave.disabled = false;
      afterSave.classList.add('primary');
    }
  });

  // Подсветка текущего раздела в шапке.
  const parts = location.pathname.split('/');
  // Витрина демо: сервисы относятся к «Ключам», остальное к своему пункту меню
  const section = parts[1] === 'showcase'
    ? (parts[2] === 'services' ? '/keys' : `/showcase/${parts[2]}`)
    : '/' + (parts[1] || 'keys');
  document.querySelectorAll('.nav a[href]').forEach((a) => {
    const href = a.getAttribute('href');
    if (href === section || (section === '/audit' && href === '/settings')) a.setAttribute('aria-current', 'page');
  });

  const focusTarget = document.querySelector('input[autofocus]');
  if (focusTarget && document.activeElement === document.body) {
    focusTarget.focus();
  }
})();
