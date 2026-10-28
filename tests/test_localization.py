import io
import http.server
import threading
import urllib.request
import unittest
import xml.etree.ElementTree as ET
import zipfile

import dashboard


MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def translation_strings(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from translation_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from translation_strings(item)
    elif isinstance(value, str):
        yield value


def workbook_rows(data):
    with zipfile.ZipFile(io.BytesIO(data)) as workbook:
        xml = ET.fromstring(workbook.read("xl/worksheets/sheet1.xml"))
    rows = xml.findall(".//{%s}row" % MAIN_NS)
    return [
        ["".join(cell.itertext()) for cell in row.findall("{%s}c" % MAIN_NS)]
        for row in rows
    ]


class LocalizationTests(unittest.TestCase):
    def setUp(self):
        with dashboard.history_lock:
            self.original_history = list(dashboard.history)
            dashboard.history[:] = [
                {
                    "record_type": "event",
                    "event_type": "tool.call",
                    "tool_name": "Bash",
                    "command": "echo unchanged",
                }
            ]

    def tearDown(self):
        with dashboard.history_lock:
            dashboard.history[:] = self.original_history

    def test_only_supported_languages_are_selected(self):
        self.assertEqual(dashboard.normalize_language("en"), "en")
        self.assertEqual(dashboard.normalize_language("zh-TW"), "zh-TW")
        for language in ("zh-CN", "zh-HK", "zh-SG", "zh-Hant-TW", "fr"):
            with self.subTest(language=language):
                self.assertEqual(dashboard.normalize_language(language), "en")

    def test_translation_catalog_keys_match(self):
        self.assertEqual(
            set(dashboard.TRANSLATIONS["en"]),
            set(dashboard.TRANSLATIONS["zh-TW"]),
        )
        for group in (
            "record_types", "severities", "decisions_map", "event_types",
            "indicator_types", "diagnostic_levels",
        ):
            with self.subTest(group=group):
                self.assertEqual(
                    set(dashboard.TRANSLATIONS["en"][group]),
                    set(dashboard.TRANSLATIONS["zh-TW"][group]),
                )

    def test_taiwan_catalog_excludes_known_non_taiwan_terms(self):
        text = "\n".join(translation_strings(dashboard.TRANSLATIONS["zh-TW"]))
        for term in dashboard.NON_TAIWAN_TERMS:
            with self.subTest(term=term):
                self.assertNotIn(term, text)

    def test_known_assistant_event_has_a_taiwan_label(self):
        self.assertEqual(
            dashboard.TRANSLATIONS["zh-TW"]["event_types"]["message.assistant"],
            "助理訊息",
        )

    def test_archives_link_does_not_inherit_the_opener_tab_language(self):
        self.assertIn('target="_blank" rel="noopener"', dashboard.PAGE)

    def test_xlsx_headers_follow_language_and_leave_record_values_unchanged(self):
        english_rows = workbook_rows(dashboard.build_xlsx("en"))
        chinese_rows = workbook_rows(dashboard.build_xlsx("zh-TW"))

        self.assertEqual(english_rows[0], dashboard.TRANSLATIONS["en"]["xlsx_headers"])
        self.assertEqual(chinese_rows[0], dashboard.TRANSLATIONS["zh-TW"]["xlsx_headers"])
        self.assertEqual(english_rows[1], chinese_rows[1])
        self.assertEqual(english_rows[1][1], "event")
        self.assertEqual(english_rows[1][14], "echo unchanged")

    def test_unsupported_xlsx_language_falls_back_to_english(self):
        rows = workbook_rows(dashboard.build_xlsx("zh-CN"))
        self.assertEqual(rows[0], dashboard.TRANSLATIONS["en"]["xlsx_headers"])

    def test_export_endpoint_uses_language_query_and_english_fallback(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), dashboard.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            cases = (
                ("?lang=zh-TW", "zh-TW"),
                ("?lang=en", "en"),
                ("?lang=zh-CN", "en"),
                ("", "en"),
            )
            for query, language in cases:
                with self.subTest(query=query):
                    url = "http://127.0.0.1:%d/export.xlsx%s" % (server.server_port, query)
                    with urllib.request.urlopen(url) as response:
                        rows = workbook_rows(response.read())
                    self.assertEqual(rows[0], dashboard.TRANSLATIONS[language]["xlsx_headers"])
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    def test_templates_receive_the_shared_language_runtime(self):
        page = dashboard.render_template(dashboard.PAGE)
        archives = dashboard.render_template(
            dashboard.ARCHIVES_TMPL.replace("{{ROWS}}", "")
        )
        for rendered in (page, archives):
            with self.subTest(page=rendered[:40]):
                self.assertNotIn("{{I18N_SCRIPT}}", rendered)
                self.assertIn('value="zh-TW"', rendered)
                self.assertIn("numbat-dashboard-language", rendered)
                self.assertIn("AI 代理程式即時監看", rendered)


if __name__ == "__main__":
    unittest.main()
