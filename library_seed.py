"""Built-in vulnerability templates, added to the library on the first run.
Scores are computed from the vectors by cvss.py, so they always match the calculator."""


def _p(*paras):
    return "".join("<p>%s</p>" % p for p in paras)


def _ul(*items):
    return "<ul>%s</ul>" % "".join("<li>%s</li>" % i for i in items)


def _refs(*links):
    return _ul(*['<a href="%s">%s</a>' % (u, t) for t, u in links])


SEED = [
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "refs": _refs(("OWASP: SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
                      ("OWASP Cheat Sheet: SQL Injection Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html")),
        "ru": {
            "title": "Внедрение SQL-кода (SQL Injection)",
            "description": _p("Приложение подставляет данные, полученные от пользователя, в SQL-запрос без экранирования и параметризации. "
                              "Это позволяет злоумышленнику изменить логику запроса к базе данных."),
            "impact": _p("Чтение, изменение и удаление данных в СУБД, обход аутентификации, в ряде случаев — выполнение команд ОС на сервере БД."),
            "recommendation": _ul("Использовать параметризованные запросы (prepared statements) или ORM.",
                                  "Проверять входные данные по белому списку допустимых значений.",
                                  "Выполнять запросы от учётной записи СУБД с минимальными привилегиями."),
        },
        "en": {
            "title": "SQL Injection",
            "description": _p("The application inserts user-supplied data into an SQL query without escaping or parameterisation, "
                              "letting an attacker change the logic of the database query."),
            "impact": _p("Reading, modifying and deleting database data, authentication bypass and, in some cases, OS command execution on the DB server."),
            "recommendation": _ul("Use parameterised queries (prepared statements) or an ORM.",
                                  "Validate input against an allow-list.",
                                  "Run queries under a least-privilege database account."),
        },
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "refs": _refs(("OWASP: Command Injection", "https://owasp.org/www-community/attacks/Command_Injection")),
        "ru": {
            "title": "Внедрение команд ОС (OS Command Injection)",
            "description": _p("Пользовательские данные передаются в командную оболочку операционной системы без фильтрации, "
                              "что позволяет выполнить произвольные команды на сервере."),
            "impact": _p("Полная компрометация сервера: выполнение кода, доступ к данным и учётным данным, продвижение во внутреннюю сеть."),
            "recommendation": _ul("Не вызывать командную оболочку с пользовательскими данными; использовать API языка.",
                                  "Если вызов неизбежен — передавать аргументы списком и проверять их по белому списку.",
                                  "Запускать приложение с минимальными привилегиями."),
        },
        "en": {
            "title": "OS Command Injection",
            "description": _p("User input is passed to an operating-system shell without filtering, allowing arbitrary commands to run on the server."),
            "impact": _p("Full server compromise: code execution, access to data and credentials, lateral movement into the internal network."),
            "recommendation": _ul("Avoid calling a shell with user input; use language APIs instead.",
                                  "If unavoidable, pass arguments as a list and validate them against an allow-list.",
                                  "Run the application with least privilege."),
        },
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "refs": _refs(("OWASP WSTG: Testing for Default Credentials", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials")),
        "ru": {
            "title": "Использование учётных данных по умолчанию",
            "description": _p("Для доступа к интерфейсу администрирования используются стандартные учётные данные производителя, опубликованные в документации."),
            "impact": _p("Получение административного доступа к системе без каких-либо специальных знаний."),
            "recommendation": _ul("Сменить все учётные данные по умолчанию на уникальные стойкие пароли.",
                                  "Ограничить доступ к интерфейсам администрирования по сети.",
                                  "Включить многофакторную аутентификацию."),
        },
        "en": {
            "title": "Default credentials",
            "description": _p("The administration interface accepts the vendor's default credentials, which are published in the documentation."),
            "impact": _p("Administrative access to the system without any special knowledge."),
            "recommendation": _ul("Replace all default credentials with unique strong passwords.",
                                  "Restrict network access to administration interfaces.",
                                  "Enable multi-factor authentication."),
        },
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
        "refs": _refs(("OWASP: Server Side Request Forgery", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery")),
        "ru": {
            "title": "Подделка запросов на стороне сервера (SSRF)",
            "description": _p("Приложение выполняет HTTP-запросы по адресу, заданному пользователем, без проверки назначения. "
                              "Это позволяет обращаться от имени сервера к внутренним ресурсам."),
            "impact": _p("Доступ к внутренним сервисам и метаданным облачной инфраструктуры, сканирование внутренней сети, обход межсетевого экранирования."),
            "recommendation": _ul("Разрешать запросы только к адресам из белого списка.",
                                  "Запрещать обращения к внутренним и loopback-адресам после разрешения DNS.",
                                  "Отключить неиспользуемые схемы URL (file://, gopher:// и т.п.)."),
        },
        "en": {
            "title": "Server-Side Request Forgery (SSRF)",
            "description": _p("The application makes HTTP requests to a user-supplied address without validating the destination, "
                              "so internal resources can be reached on the server's behalf."),
            "impact": _p("Access to internal services and cloud metadata, internal network scanning, firewall bypass."),
            "recommendation": _ul("Allow requests only to allow-listed destinations.",
                                  "Block internal and loopback addresses after DNS resolution.",
                                  "Disable unused URL schemes (file://, gopher://, etc.)."),
        },
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "refs": _refs(("OWASP: Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal")),
        "ru": {
            "title": "Обход каталога (Path Traversal)",
            "description": _p("Имя файла, полученное от пользователя, используется для доступа к файловой системе без нормализации пути. "
                              "Последовательности вида <code>../</code> позволяют выйти за пределы разрешённого каталога."),
            "impact": _p("Чтение произвольных файлов сервера, включая конфигурацию, исходный код и учётные данные."),
            "recommendation": _ul("Не использовать пользовательский ввод в путях к файлам; применять идентификаторы.",
                                  "Нормализовать путь и проверять, что он остаётся внутри разрешённого каталога."),
        },
        "en": {
            "title": "Path Traversal",
            "description": _p("A user-supplied file name is used to access the file system without path normalisation. "
                              "Sequences like <code>../</code> escape the intended directory."),
            "impact": _p("Reading arbitrary server files, including configuration, source code and credentials."),
            "recommendation": _ul("Do not use user input in file paths; use identifiers instead.",
                                  "Normalise the path and verify it stays inside the allowed directory."),
        },
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "refs": _refs(("OWASP Top 10: Vulnerable and Outdated Components", "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/")),
        "ru": {
            "title": "Использование устаревшего ПО с известными уязвимостями",
            "description": _p("На сервере используется версия программного обеспечения, для которой опубликованы уязвимости (CVE) и общедоступные эксплойты."),
            "impact": _p("Последствия зависят от конкретных уязвимостей: от раскрытия информации до выполнения произвольного кода."),
            "recommendation": _ul("Обновить ПО до актуальной поддерживаемой версии.",
                                  "Внедрить процесс регулярного контроля и установки обновлений безопасности."),
        },
        "en": {
            "title": "Outdated software with known vulnerabilities",
            "description": _p("The server runs a software version with published vulnerabilities (CVEs) and public exploits."),
            "impact": _p("Depends on the specific vulnerabilities: from information disclosure to arbitrary code execution."),
            "recommendation": _ul("Update the software to a current supported version.",
                                  "Introduce a regular patch-management process."),
        },
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "refs": _refs(("OWASP: Cross Site Scripting", "https://owasp.org/www-community/attacks/xss/"),
                      ("OWASP Cheat Sheet: XSS Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html")),
        "ru": {
            "title": "Межсайтовое выполнение сценариев (Reflected XSS)",
            "description": _p("Значение параметра запроса возвращается в HTML-ответе без кодирования, что позволяет внедрить JavaScript-код "
                              "в страницу при переходе пользователя по специально сформированной ссылке."),
            "impact": _p("Выполнение действий от имени пользователя, кража данных со страницы, фишинг в доверенном домене."),
            "recommendation": _ul("Кодировать выводимые данные в соответствии с контекстом (HTML, атрибут, JavaScript, URL).",
                                  "Внедрить политику Content-Security-Policy.",
                                  "Устанавливать для cookie сессии флаги HttpOnly и Secure."),
        },
        "en": {
            "title": "Reflected Cross-Site Scripting (XSS)",
            "description": _p("A request parameter is echoed in the HTML response without encoding, allowing JavaScript to be injected "
                              "when a user follows a crafted link."),
            "impact": _p("Actions performed as the victim, theft of page data, phishing on a trusted domain."),
            "recommendation": _ul("Encode output for its context (HTML, attribute, JavaScript, URL).",
                                  "Deploy a Content-Security-Policy.",
                                  "Set HttpOnly and Secure flags on session cookies."),
        },
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "refs": _refs(("OWASP: Cross Site Scripting", "https://owasp.org/www-community/attacks/xss/")),
        "ru": {
            "title": "Межсайтовое выполнение сценариев (Stored XSS)",
            "description": _p("Данные, сохранённые пользователем, отображаются другим пользователям без кодирования, "
                              "что позволяет внедрить постоянный JavaScript-код в страницы приложения."),
            "impact": _p("Выполнение кода в браузере каждого пользователя, открывшего страницу, в том числе администраторов."),
            "recommendation": _ul("Кодировать выводимые данные в соответствии с контекстом.",
                                  "Очищать HTML-разметку, если она допускается, с помощью проверенной библиотеки.",
                                  "Внедрить политику Content-Security-Policy."),
        },
        "en": {
            "title": "Stored Cross-Site Scripting (XSS)",
            "description": _p("Data saved by one user is shown to other users without encoding, allowing persistent JavaScript injection."),
            "impact": _p("Code execution in the browser of every user who opens the page, including administrators."),
            "recommendation": _ul("Encode output for its context.",
                                  "Sanitise HTML with a vetted library where markup is allowed.",
                                  "Deploy a Content-Security-Policy."),
        },
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "refs": _refs(("OWASP: Insecure Direct Object Reference", "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html")),
        "ru": {
            "title": "Небезопасные прямые ссылки на объекты (IDOR)",
            "description": _p("Приложение не проверяет, принадлежит ли запрашиваемый объект текущему пользователю. "
                              "Изменив идентификатор в запросе, можно получить доступ к данным других пользователей."),
            "impact": _p("Несанкционированный доступ к персональным и финансовым данным других клиентов."),
            "recommendation": _ul("Проверять права доступа к каждому объекту на стороне сервера.",
                                  "Использовать непредсказуемые идентификаторы (UUID) как дополнительную меру."),
        },
        "en": {
            "title": "Insecure Direct Object Reference (IDOR)",
            "description": _p("The application does not check that the requested object belongs to the current user. "
                              "Changing the identifier in the request exposes other users' data."),
            "impact": _p("Unauthorised access to other customers' personal and financial data."),
            "recommendation": _ul("Enforce object-level authorisation on the server for every request.",
                                  "Use unpredictable identifiers (UUIDs) as defence in depth."),
        },
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "refs": _refs(("OWASP: Cross Site Request Forgery", "https://owasp.org/www-community/attacks/csrf")),
        "ru": {
            "title": "Подделка межсайтовых запросов (CSRF)",
            "description": _p("Изменяющие состояние запросы не защищены токеном и не проверяют источник, поэтому сторонний сайт "
                              "может отправить их от имени авторизованного пользователя."),
            "impact": _p("Выполнение действий от имени пользователя: изменение настроек, данных профиля, проведение операций."),
            "recommendation": _ul("Использовать анти-CSRF токены для всех изменяющих запросов.",
                                  "Устанавливать для cookie сессии атрибут SameSite=Lax или Strict."),
        },
        "en": {
            "title": "Cross-Site Request Forgery (CSRF)",
            "description": _p("State-changing requests have no token and no origin check, so a third-party site can submit them on behalf of a logged-in user."),
            "impact": _p("Actions performed as the user: changing settings or profile data, performing transactions."),
            "recommendation": _ul("Use anti-CSRF tokens on all state-changing requests.",
                                  "Set SameSite=Lax or Strict on session cookies."),
        },
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "refs": _refs(("OWASP Cheat Sheet: Authentication", "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html")),
        "ru": {
            "title": "Отсутствие защиты от подбора паролей",
            "description": _p("Форма аутентификации не ограничивает количество неудачных попыток входа и не использует CAPTCHA или задержки."),
            "impact": _p("Подбор паролей пользователей методом перебора или по словарю и получение доступа к их учётным записям."),
            "recommendation": _ul("Ограничить число попыток входа и вводить нарастающую задержку.",
                                  "Включить многофакторную аутентификацию.",
                                  "Отслеживать и оповещать о массовых неудачных попытках входа."),
        },
        "en": {
            "title": "No brute-force protection",
            "description": _p("The login form does not limit failed attempts and uses no CAPTCHA or delays."),
            "impact": _p("Users' passwords can be guessed by brute force or dictionary attacks, giving access to their accounts."),
            "recommendation": _ul("Limit login attempts and add increasing delays.",
                                  "Enable multi-factor authentication.",
                                  "Monitor and alert on mass failed logins."),
        },
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "refs": _refs(("OWASP WSTG: Testing for Improper Error Handling", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling")),
        "ru": {
            "title": "Раскрытие технической информации в сообщениях об ошибках",
            "description": _p("При возникновении ошибки приложение возвращает подробное сообщение: трассировку стека, версии ПО, пути к файлам, фрагменты запросов."),
            "impact": _p("Злоумышленник получает сведения, облегчающие подготовку и проведение других атак."),
            "recommendation": _ul("Возвращать пользователю обобщённое сообщение об ошибке.",
                                  "Записывать подробности ошибок только в журналы на сервере.",
                                  "Отключить режим отладки в продуктивной среде."),
        },
        "en": {
            "title": "Information disclosure in error messages",
            "description": _p("On errors the application returns detailed messages: stack traces, software versions, file paths, query fragments."),
            "impact": _p("The attacker learns details that make other attacks easier."),
            "recommendation": _ul("Show users a generic error message.",
                                  "Log error details on the server only.",
                                  "Disable debug mode in production."),
        },
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "refs": _refs(("Mozilla: Server Side TLS", "https://wiki.mozilla.org/Security/Server_Side_TLS")),
        "ru": {
            "title": "Небезопасная конфигурация TLS",
            "description": _p("Сервер поддерживает устаревшие версии протокола (TLS 1.0/1.1) и/или слабые наборы шифров."),
            "impact": _p("При наличии позиции «человек посередине» возможно снижение стойкости защиты передаваемых данных."),
            "recommendation": _ul("Отключить TLS 1.0 и 1.1, оставить TLS 1.2 и 1.3.",
                                  "Оставить только стойкие наборы шифров с прямой секретностью (ECDHE).",
                                  "Включить заголовок Strict-Transport-Security."),
        },
        "en": {
            "title": "Insecure TLS configuration",
            "description": _p("The server supports legacy protocol versions (TLS 1.0/1.1) and/or weak cipher suites."),
            "impact": _p("An attacker in a man-in-the-middle position may weaken the protection of data in transit."),
            "recommendation": _ul("Disable TLS 1.0 and 1.1; keep TLS 1.2 and 1.3.",
                                  "Allow only strong cipher suites with forward secrecy (ECDHE).",
                                  "Enable the Strict-Transport-Security header."),
        },
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "refs": _refs(("OWASP Secure Headers Project", "https://owasp.org/www-project-secure-headers/")),
        "ru": {
            "title": "Отсутствие заголовков безопасности HTTP",
            "description": _p("В ответах сервера отсутствуют заголовки Content-Security-Policy, X-Frame-Options, "
                              "Strict-Transport-Security, X-Content-Type-Options."),
            "impact": _p("Снижается защищённость клиентов от атак clickjacking, XSS и понижения протокола до HTTP."),
            "recommendation": _ul("Добавить заголовки безопасности в конфигурацию веб-сервера или приложения.",
                                  "Проверить конфигурацию после внедрения (например, securityheaders.com)."),
        },
        "en": {
            "title": "Missing HTTP security headers",
            "description": _p("Responses lack Content-Security-Policy, X-Frame-Options, Strict-Transport-Security and X-Content-Type-Options."),
            "impact": _p("Clients are less protected from clickjacking, XSS and protocol downgrade."),
            "recommendation": _ul("Add the security headers in the web server or application configuration.",
                                  "Verify the configuration after deployment."),
        },
    },
]


def seed_templates():
    out = []
    for item in SEED:
        for lang in ("ru", "en"):
            t = dict(item[lang])
            t.update(lang=lang, cvss_vector=item["vector"], refs=item["refs"])
            out.append(t)
    return out
