package net.minidev.json.test;

import junit.framework.TestCase;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

public class TestOverflow extends TestCase {

	public void testDeepNestingOverflow() throws Exception {
		int size = 10000;
		StringBuilder sb = new StringBuilder(10 + size * 4);
		for (int i = 0; i < size; i++) {
			sb.append("{a:");
		}
		sb.append("true");
		for (int i = 0; i < size; i++) {
			sb.append("}");
		}
		String s = sb.toString();

		try {
			new JSONParser(JSONParser.MODE_PERMISSIVE).parse(s);
			fail("Expected ParseException due to excessive nesting");
		} catch (ParseException e) {
			assertEquals(ParseException.ERROR_UNEXPECTED_JSON_DEPTH, e.getErrorType());
		}
	}
}
