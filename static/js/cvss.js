/* CVSS v3.1 base score calculator (FIRST specification). Mirrors cvss.py. */
(function () {
  'use strict';

  var W = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 }
  };
  var PR = { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } };
  var ORDER = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

  // Plain-language questions so the calculator can be used without knowing the spec by heart.
  var METRICS = {
    ru: [
      { key: 'AV', name: 'Откуда возможна атака', hint: 'Attack Vector', options: [
        ['N', 'Из интернета / сети', 'Атакующему достаточно сетевого доступа, в т.ч. через интернет'],
        ['A', 'Из соседней сети', 'Тот же сегмент: Wi-Fi, VLAN, Bluetooth'],
        ['L', 'Локально', 'Нужен доступ к системе (сессия, SSH) или действие пользователя с файлом'],
        ['P', 'Физически', 'Нужен физический доступ к устройству']] },
      { key: 'AC', name: 'Сложность атаки', hint: 'Attack Complexity', options: [
        ['L', 'Низкая', 'Атаку можно повторять надёжно, особых условий нет'],
        ['H', 'Высокая', 'Нужны особые условия: гонка, MitM, знание секретов окружения']] },
      { key: 'PR', name: 'Нужны ли права', hint: 'Privileges Required', options: [
        ['N', 'Не нужны', 'Анонимный атакующий'],
        ['L', 'Пользователя', 'Обычная учётная запись'],
        ['H', 'Администратора', 'Привилегированная учётная запись']] },
      { key: 'UI', name: 'Нужно ли действие жертвы', hint: 'User Interaction', options: [
        ['N', 'Нет', 'Атака проходит без участия пользователя'],
        ['R', 'Да', 'Жертва должна перейти по ссылке, открыть файл и т.п.']] },
      { key: 'S', name: 'Выходит ли ущерб за пределы компонента', hint: 'Scope', options: [
        ['U', 'Нет', 'Страдает только уязвимый компонент'],
        ['C', 'Да', 'Затрагиваются другие компоненты: браузер пользователя (XSS), внутренняя сеть (SSRF), хост (выход из контейнера)']] },
      { key: 'C', name: 'Конфиденциальность', hint: 'Confidentiality', options: [
        ['H', 'Высокое влияние', 'Доступ ко всем данным или к критичным (пароли, ключи)'],
        ['L', 'Низкое', 'Доступ к части данных без контроля над выбором'],
        ['N', 'Нет', '']] },
      { key: 'I', name: 'Целостность', hint: 'Integrity', options: [
        ['H', 'Высокое влияние', 'Можно изменить любые или критичные данные'],
        ['L', 'Низкое', 'Ограниченное изменение данных'],
        ['N', 'Нет', '']] },
      { key: 'A', name: 'Доступность', hint: 'Availability', options: [
        ['H', 'Высокое влияние', 'Полный отказ в обслуживании'],
        ['L', 'Низкое', 'Снижение производительности, частичные перебои'],
        ['N', 'Нет', '']] }
    ],
    en: [
      { key: 'AV', name: 'Where can the attack come from', hint: 'Attack Vector', options: [
        ['N', 'Network / Internet', 'Remote network access is enough'],
        ['A', 'Adjacent network', 'Same segment: Wi-Fi, VLAN, Bluetooth'],
        ['L', 'Local', 'Needs a session on the system or a user opening a file'],
        ['P', 'Physical', 'Needs physical access to the device']] },
      { key: 'AC', name: 'Attack complexity', hint: 'Attack Complexity', options: [
        ['L', 'Low', 'Reliably repeatable, no special conditions'],
        ['H', 'High', 'Needs special conditions: race, MitM, knowledge of the environment']] },
      { key: 'PR', name: 'Privileges required', hint: 'Privileges Required', options: [
        ['N', 'None', 'Anonymous attacker'],
        ['L', 'User', 'A regular account'],
        ['H', 'Admin', 'A privileged account']] },
      { key: 'UI', name: 'Victim interaction', hint: 'User Interaction', options: [
        ['N', 'None', 'No user involvement'],
        ['R', 'Required', 'The victim must click a link, open a file, etc.']] },
      { key: 'S', name: 'Does the impact reach other components', hint: 'Scope', options: [
        ['U', 'No', 'Only the vulnerable component is affected'],
        ['C', 'Yes', 'Other components are affected: the user\'s browser (XSS), internal network (SSRF), host (container escape)']] },
      { key: 'C', name: 'Confidentiality', hint: 'Confidentiality', options: [
        ['H', 'High', 'All data or critical data (passwords, keys)'], ['L', 'Low', 'Some data, attacker cannot choose'], ['N', 'None', '']] },
      { key: 'I', name: 'Integrity', hint: 'Integrity', options: [
        ['H', 'High', 'Any or critical data can be modified'], ['L', 'Low', 'Limited modification'], ['N', 'None', '']] },
      { key: 'A', name: 'Availability', hint: 'Availability', options: [
        ['H', 'High', 'Full denial of service'], ['L', 'Low', 'Degraded performance, partial outages'], ['N', 'None', '']] }
    ]
  };

  function roundup(x) {
    var i = Math.round(x * 100000);
    return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
  }

  function severity(score) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    if (score > 0) return 'low';
    return 'info';
  }

  function score(m) {
    if (ORDER.some(function (k) { return !m[k]; })) return null;
    var iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
    var impact = m.S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    var expl = 8.22 * W.AV[m.AV] * W.AC[m.AC] * PR[m.S][m.PR] * W.UI[m.UI];
    if (impact <= 0) return 0;
    return m.S === 'U' ? roundup(Math.min(impact + expl, 10)) : roundup(Math.min(1.08 * (impact + expl), 10));
  }

  function parse(vector) {
    var m = {};
    String(vector || '').trim().split('/').forEach(function (part) {
      var kv = part.split(':');
      if (kv.length === 2 && ORDER.indexOf(kv[0]) >= 0) m[kv[0]] = kv[1];
    });
    return m;
  }

  function build(m) {
    return 'CVSS:3.1/' + ORDER.map(function (k) { return k + ':' + m[k]; }).join('/');
  }

  window.CVSS = { METRICS: METRICS, ORDER: ORDER, score: score, severity: severity, parse: parse, build: build };
})();
