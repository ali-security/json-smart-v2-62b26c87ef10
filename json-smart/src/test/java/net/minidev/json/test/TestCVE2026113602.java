package net.minidev.json.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

import org.junit.Test;

/**
 * CVE-2026-113602: a literal 0x1A char (the internal EOI marker) must not be
 * handled as the end of input by the strict trailing data check.
 */
public class TestCVE2026113602 {

	private static final String[] MALICIOUS = { //
			"{}\u001A{garbage", //
			"{\"a\":1}\u001A{bad}", //
			"[1]\u001Axx", //
			"1\u001Axx", //
			"1.5\u001Axx", //
			"true\u001Afalse", //
			"null\u001Axx", //
			"\"s\"\u001Axx", //
			"{} \u001A garbage", //
			"{}\u001A", //
			"{} \u001A", //
	};

	private static final String[] VALID = { "{}", "[1]", "1", "1.5", "true", "null", "\"s\"", "{\"a\":1}" };

	private static final int[] STRICT_MODES = { JSONParser.MODE_RFC4627, JSONParser.MODE_STRICTEST };

	private interface Parse {
		Object run() throws Exception;
	}

	private static ParseException assertThrows(Parse parse, String message) throws Exception {
		try {
			parse.run();
		} catch (ParseException e) {
			return e;
		}
		fail(message);
		return null;
	}

	private static byte[] bytes(String s) throws UnsupportedEncodingException {
		return s.getBytes("UTF-8");
	}

	private static Parse parseString(final JSONParser p, final String s) {
		return new Parse() {
			public Object run() throws Exception {
				return p.parse(s);
			}
		};
	}

	private static Parse parseBytes(final JSONParser p, final String s) {
		return new Parse() {
			public Object run() throws Exception {
				return p.parse(bytes(s));
			}
		};
	}

	private static Parse parseReader(final JSONParser p, final String s) {
		return new Parse() {
			public Object run() throws Exception {
				return p.parse(new StringReader(s));
			}
		};
	}

	private static Parse parseInputStream(final JSONParser p, final String s) {
		return new Parse() {
			public Object run() throws Exception {
				return p.parse(new ByteArrayInputStream(bytes(s)));
			}
		};
	}

	@Test
	public void isValidJsonStrictStringRejectsLiteralEOI() {
		for (String s : MALICIOUS)
			assertFalse("must be invalid: " + s, JSONValue.isValidJsonStrict(s));
	}

	@Test
	public void isValidJsonStrictReaderRejectsLiteralEOI() throws Exception {
		for (String s : MALICIOUS)
			assertFalse("must be invalid: " + s, JSONValue.isValidJsonStrict(new StringReader(s)));
	}

	@Test
	public void parseStrictStringRejectsLiteralEOI() throws Exception {
		for (final String s : MALICIOUS)
			assertThrows(new Parse() {
				public Object run() throws Exception {
					return JSONValue.parseStrict(s);
				}
			}, "must throw: " + s);
	}

	@Test
	public void parseStrictReaderRejectsLiteralEOI() throws Exception {
		for (final String s : MALICIOUS)
			assertThrows(new Parse() {
				public Object run() throws Exception {
					return JSONValue.parseStrict(new StringReader(s));
				}
			}, "must throw: " + s);
	}

	@Test
	public void strictModesRejectLiteralEOIOnAllInputs() throws Exception {
		for (int mode : STRICT_MODES) {
			for (String s : MALICIOUS) {
				JSONParser p = new JSONParser(mode);
				assertThrows(parseString(p, s), "String must throw: " + s);
				assertThrows(parseBytes(p, s), "byte[] must throw: " + s);
				assertThrows(parseReader(p, s), "Reader must throw: " + s);
				assertThrows(parseInputStream(p, s), "InputStream must throw: " + s);
			}
		}
	}

	@Test
	public void literalEOIIsReportedAsUnexpectedToken() throws Exception {
		String s = "{\"a\":1}\u001A{bad}";
		JSONParser p = new JSONParser(JSONParser.MODE_RFC4627);
		ParseException e = assertThrows(parseString(p, s), "must throw: " + s);
		assertEquals(ParseException.ERROR_UNEXPECTED_TOKEN, e.getErrorType());
		e = assertThrows(parseBytes(p, s), "must throw: " + s);
		assertEquals(ParseException.ERROR_UNEXPECTED_TOKEN, e.getErrorType());
		e = assertThrows(parseReader(p, s), "must throw: " + s);
		assertEquals(ParseException.ERROR_UNEXPECTED_TOKEN, e.getErrorType());
		e = assertThrows(parseInputStream(p, s), "must throw: " + s);
		assertEquals(ParseException.ERROR_UNEXPECTED_TOKEN, e.getErrorType());
	}

	@Test
	public void strictModesRejectLiteralEOIInString() throws Exception {
		String s = "{\"a\":\"x\u001Ay\"}";
		for (int mode : STRICT_MODES) {
			JSONParser p = new JSONParser(mode);
			assertThrows(parseString(p, s), "String must throw: " + s);
			assertThrows(parseBytes(p, s), "byte[] must throw: " + s);
			assertThrows(parseReader(p, s), "Reader must throw: " + s);
			assertThrows(parseInputStream(p, s), "InputStream must throw: " + s);
		}
	}

	@Test
	public void strictModesStillAcceptValidJson() throws Exception {
		for (int mode : STRICT_MODES) {
			JSONParser p = new JSONParser(mode);
			for (String s : VALID) {
				p.parse(s);
				p.parse(bytes(s));
				p.parse(new StringReader(s));
				p.parse(new ByteArrayInputStream(bytes(s)));
				assertTrue("must be valid: " + s, JSONValue.isValidJsonStrict(s));
				assertTrue("must be valid: " + s, JSONValue.isValidJsonStrict(new StringReader(s)));
			}
		}
		// trailing spaces are still accepted in RFC4627 mode
		JSONParser p = new JSONParser(JSONParser.MODE_RFC4627);
		assertEquals(new JSONObject(), p.parse("{} "));
		assertEquals(new JSONObject(), p.parse(bytes("{} \n")));
		assertEquals(new JSONObject(), p.parse(new StringReader("{}\t ")));
		assertEquals(new JSONObject(), p.parse(new ByteArrayInputStream(bytes("{}\r\n"))));
	}

	@Test
	public void parserReuseKeepsCheckingLiteralEOI() throws Exception {
		JSONParser p = new JSONParser(JSONParser.MODE_RFC4627);
		JSONArray a = (JSONArray) p.parse(new StringReader("[1]"));
		assertEquals(1, a.size());
		assertThrows(parseReader(p, "[1]\u001Axx"), "must throw");
		a = (JSONArray) p.parse(new StringReader("[1]"));
		assertEquals(1, a.size());
		assertThrows(parseInputStream(p, "[1]\u001Axx"), "must throw");
		assertNull(p.parse(new ByteArrayInputStream(bytes("null"))));
	}

	@Test
	public void permissiveModeIsUnchanged() throws Exception {
		// permissive mode accepts trailing data, literal 0x1A included
		JSONParser p = new JSONParser(JSONParser.MODE_PERMISSIVE);
		assertEquals(new JSONObject(), p.parse("{}\u001Agarbage"));
		assertEquals(new JSONObject(), p.parse(new StringReader("{}\u001Agarbage")));
	}
}
