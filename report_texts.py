"""Fixed wording of the report template. Every report is rendered from these labels,
so all reports share the same structure, headings and rating scale."""

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# Document classification ("гриф"). Stored as a key; the label comes from LABELS[lang]["classes"].
CLASSIFICATIONS = ["strict", "confidential", "internal", "public", "test"]
CLASS_COLORS = {"strict": "#8E1B3B", "confidential": "#E5484D", "internal": "#D97706",
                "public": "#21A038", "test": "#6B7280"}

# Callout blocks that can be inserted into any text section.
CALLOUTS = ["note", "warning", "danger", "tip"]

LABELS = {
    "ru": {
        "severity": {"critical": "Критический", "high": "Высокий", "medium": "Средний",
                     "low": "Низкий", "info": "Информационный"},
        "status": {"open": "Открыта", "fixed": "Устранена", "accepted": "Риск принят",
                   "retest": "На перепроверке"},
        "report": "Отчёт",
        "cover_kind": "Отчёт о тестировании на проникновение",
        "client": "Заказчик",
        "system": "Объект тестирования",
        "test_type": "Вид работ",
        "period": "Период проведения",
        "version": "Версия документа",
        "authors": "Исполнители",
        "classification": "Гриф",
        "date": "Дата формирования",
        "doc_control": "Сведения о документе",
        "toc": "Содержание",
        "s_exec": "Резюме для руководства",
        "s_scope": "Область тестирования",
        "s_method": "Методология",
        "s_summary": "Сводка уязвимостей",
        "s_details": "Детальное описание уязвимостей",
        "s_concl": "Заключение",
        "a_scale": "Шкала оценки критичности",
        "stats": "Распределение уязвимостей по уровню критичности",
        "total": "Всего",
        "id": "ID",
        "name": "Наименование",
        "level": "Критичность",
        "cvss": "CVSS",
        "vector": "Вектор CVSS",
        "cwe": "CWE",
        "assets": "Затронутые ресурсы",
        "status_l": "Статус",
        "f_description": "Описание",
        "f_impact": "Возможные последствия",
        "f_reproduction": "Шаги воспроизведения",
        "f_recommendation": "Рекомендации по устранению",
        "f_refs": "Ссылки",
        "no_findings": "Уязвимости не выявлены.",
        "classes": {"strict": "Строго конфиденциально", "confidential": "Конфиденциально",
                    "internal": "Для внутреннего использования", "public": "Не конфиденциально",
                    "test": "Тестовый отчёт"},
        "watermark": "ТЕСТ",
        "callouts": {"note": "Обратите внимание", "warning": "Внимание", "danger": "Критично",
                     "tip": "Рекомендация"},
        "page": "Стр.",
        "figure": "Рисунок",
        "caption_ph": "Описание скриншота",
        "of": "из",
        "scale": [
            ("critical", "9.0 – 10.0", "Эксплуатация тривиальна и ведёт к полной компрометации системы или данных. Требуется немедленное устранение."),
            ("high", "7.0 – 8.9", "Эксплуатация возможна без значительных усилий и ведёт к существенному ущербу. Устранение в приоритетном порядке."),
            ("medium", "4.0 – 6.9", "Эксплуатация требует особых условий; ущерб ограничен. Устранение в плановом порядке."),
            ("low", "0.1 – 3.9", "Незначительное влияние на безопасность. Устранение по возможности."),
            ("info", "0.0", "Наблюдение или рекомендация по улучшению защищённости."),
        ],
    },
    "en": {
        "severity": {"critical": "Critical", "high": "High", "medium": "Medium",
                     "low": "Low", "info": "Informational"},
        "status": {"open": "Open", "fixed": "Fixed", "accepted": "Risk accepted",
                   "retest": "Retest pending"},
        "report": "Report",
        "cover_kind": "Penetration Test Report",
        "client": "Client",
        "system": "Target",
        "test_type": "Engagement type",
        "period": "Testing period",
        "version": "Document version",
        "authors": "Testers",
        "classification": "Classification",
        "date": "Generated",
        "doc_control": "Document control",
        "toc": "Contents",
        "s_exec": "Executive summary",
        "s_scope": "Scope",
        "s_method": "Methodology",
        "s_summary": "Findings overview",
        "s_details": "Detailed findings",
        "s_concl": "Conclusion",
        "a_scale": "Severity rating scale",
        "stats": "Findings by severity",
        "total": "Total",
        "id": "ID",
        "name": "Title",
        "level": "Severity",
        "cvss": "CVSS",
        "vector": "CVSS vector",
        "cwe": "CWE",
        "assets": "Affected assets",
        "status_l": "Status",
        "f_description": "Description",
        "f_impact": "Impact",
        "f_reproduction": "Steps to reproduce",
        "f_recommendation": "Remediation",
        "f_refs": "References",
        "no_findings": "No vulnerabilities were identified.",
        "classes": {"strict": "Strictly confidential", "confidential": "Confidential",
                    "internal": "Internal use only", "public": "Not confidential", "test": "Test report"},
        "watermark": "TEST",
        "callouts": {"note": "Note", "warning": "Warning", "danger": "Critical", "tip": "Recommendation"},
        "page": "Page",
        "figure": "Figure",
        "caption_ph": "Screenshot description",
        "of": "of",
        "scale": [
            ("critical", "9.0 – 10.0", "Trivial to exploit; leads to full compromise of the system or data. Fix immediately."),
            ("high", "7.0 – 8.9", "Exploitable with little effort; causes significant damage. Fix as a priority."),
            ("medium", "4.0 – 6.9", "Exploitation requires specific conditions; limited damage. Fix in the regular cycle."),
            ("low", "0.1 – 3.9", "Minor security impact. Fix when possible."),
            ("info", "0.0", "Observation or hardening recommendation."),
        ],
    },
}

DEFAULT_TEXTS = {
    "ru": {
        "title": "Тестирование на проникновение",
        "test_type": "Тестирование на проникновение (Gray box)",
        "classification": "confidential",
        "executive_summary": "<p>В период с … по … проведено тестирование на проникновение … "
                             "с целью оценки защищённости от актуальных угроз.</p>"
                             "<p>По результатам работ выявлено … уязвимостей. Общий уровень защищённости оценивается как …</p>",
        "scope": "<p>В область тестирования входили следующие ресурсы:</p>"
                 "<ul><li>https://example.sberbank.ru</li><li>10.0.0.0/24</li></ul>"
                 "<p>Ограничения: тестирование отказа в обслуживании (DoS) и социальная инженерия не проводились.</p>",
        "methodology": "<p>Работы выполнялись в соответствии с методиками OWASP Web Security Testing Guide (WSTG), "
                       "PTES и NIST SP 800-115 и включали этапы:</p>"
                       "<ol><li>Сбор информации и разведка.</li><li>Анализ поверхности атаки.</li>"
                       "<li>Поиск и подтверждение уязвимостей.</li><li>Эксплуатация и оценка последствий.</li>"
                       "<li>Подготовка отчёта и рекомендаций.</li></ol>"
                       "<p>Критичность уязвимостей оценивалась по CVSS v3.1 (см. шкалу ниже).</p>",
        "conclusion": "<p>По итогам тестирования рекомендуется в приоритетном порядке устранить уязвимости "
                      "критического и высокого уровня и провести повторное тестирование.</p>",
        "finding": {"title": "Новая уязвимость", "severity": "medium",
                    "description": "<p>Опишите уязвимость.</p>",
                    "impact": "<p>Опишите возможные последствия эксплуатации.</p>",
                    "reproduction": "<ol><li>Шаг 1</li><li>Шаг 2</li></ol>",
                    "recommendation": "<p>Опишите меры по устранению.</p>"},
    },
    "en": {
        "title": "Penetration Test",
        "test_type": "Penetration test (gray box)",
        "classification": "confidential",
        "executive_summary": "<p>Between … and … a penetration test of … was carried out to assess "
                             "its resilience against current threats.</p>"
                             "<p>The assessment identified … vulnerabilities. The overall security posture is rated as …</p>",
        "scope": "<p>The following assets were in scope:</p>"
                 "<ul><li>https://app.example.com</li><li>10.0.0.0/24</li></ul>"
                 "<p>Out of scope: denial-of-service testing and social engineering.</p>",
        "methodology": "<p>Testing followed the OWASP Web Security Testing Guide (WSTG), PTES and NIST SP 800-115 "
                       "and covered these phases:</p>"
                       "<ol><li>Reconnaissance.</li><li>Attack surface analysis.</li>"
                       "<li>Vulnerability discovery and validation.</li><li>Exploitation and impact assessment.</li>"
                       "<li>Reporting and recommendations.</li></ol>"
                       "<p>Severity was rated with CVSS v3.1 (see the scale below).</p>",
        "conclusion": "<p>We recommend fixing critical and high severity issues first and scheduling a retest.</p>",
        "finding": {"title": "New finding", "severity": "medium",
                    "description": "<p>Describe the vulnerability.</p>",
                    "impact": "<p>Describe the impact of exploitation.</p>",
                    "reproduction": "<ol><li>Step 1</li><li>Step 2</li></ol>",
                    "recommendation": "<p>Describe the remediation.</p>"},
    },
}


def normalize_classification(value):
    """Map a stored value (key or a label in any language, e.g. from old reports) to a key."""
    v = (value or "").strip().lower()
    if v in CLASSIFICATIONS:
        return v
    for lang in LABELS.values():
        for key, label in lang["classes"].items():
            if label.lower() == v:
                return key
    if v in ("test", "тест", "черновик", "draft"):
        return "test"
    return "confidential"
