// Rule documentation, in one place. Both the in-app modal and rules.html render
// this exact HTML, so the two can never drift apart.
//
// String.raw, deliberately: a plain template literal eats unknown escapes, so
// "\d" would arrive as "d" and every regex example in here would silently be
// wrong. There is no ${...} or backtick in the content below -- keep it that way.
export const RULES_DOC_HTML = String.raw`

<h3>What a rule does</h3>

<p>
  A rule rewrites traffic automatically as it passes through. Nothing stops, nothing
  waits for you — unlike <strong>Intercept</strong>, where you edit one flow by hand.
  Set a rule once and every matching request or reply is changed on the way past.
</p>
<p>
  There are two kinds because they do different jobs. A <strong>body rule</strong>
  finds text in the payload and replaces it. A <strong>header rule</strong> sets one
  header to a value, or removes it.
</p>

<h3>Filling in a rule</h3>

<p>Each rule is a row of fields that reads as a sentence:</p>

<pre class="anatomy">in <b>requests</b>   URL has <b>/api/</b>   find <b>"amount":100</b>   replace with <b>"amount":1</b></pre>

<table class="rules-table">
  <thead><tr><th>Field</th><th>What it means</th><th>Leave it empty to…</th></tr></thead>
  <tbody>
    <tr>
      <td><strong>in</strong></td>
      <td>Which direction to touch: requests, replies, or both.</td>
      <td>— (pick one; "requests + replies" is the default)</td>
    </tr>
    <tr>
      <td><strong>URL has</strong></td>
      <td>Only touch flows whose URL contains this. It is a regex, so <code>/api/v\d+/</code> works.</td>
      <td>touch every URL</td>
    </tr>
    <tr>
      <td><strong>find</strong> / <strong>header</strong></td>
      <td>Body rules: the text or regex to look for. Header rules: the exact header name.</td>
      <td>nothing — a rule with no <em>find</em> is skipped</td>
    </tr>
    <tr>
      <td><strong>replace with</strong> / <strong>set to</strong></td>
      <td>What to put there.</td>
      <td>body: delete the matched text · header: <strong>remove the header</strong></td>
    </tr>
  </tbody>
</table>

<p>
  Press <strong>Apply</strong> to arm them. The toolbar then shows how many rules are
  active, and the panel says how many rows were skipped for having no <em>find</em>.
</p>

<div class="note">
  <p>
    <strong>You never type separators.</strong> Under the hood mitmproxy wants one
    packed string per rule, and picking a separator that also appears in your pattern
    used to be the most common way to break a rule. The form builds that string and
    chooses a separator that appears in neither the filter nor your <em>find</em> text.
    Press <strong>Show generated syntax</strong> if you want to see what it produced.
  </p>
</div>

<h3>Rules that need more than the form</h3>

<p>
  The form covers direction plus a URL match, which is most of what anyone needs. For
  anything else — a status code, a content type, a header condition — a rule appears as
  an <strong>advanced</strong> row holding the raw string, and you can edit it there.
  The syntax is:
</p>

<pre>|filter|find|replace</pre>

<p>
  The first character is the separator; everything after it is split on that character,
  and the last field takes whatever remains. So <code>|~c 500|oops|fine</code> means
  <em>on replies with status 500, replace "oops" with "fine"</em>. Use a separator that
  appears nowhere in the filter or the find text.
</p>

<h3>Filters — which flows to touch</h3>

<p>
  This is the language of the toolbar's <strong>Stop flows matching</strong> box, and of
  the filter inside an <strong>advanced</strong> rule row. You do not need any of it for
  an ordinary rule — the form's <em>in</em> and <em>URL has</em> fields generate
  <code>~q</code>, <code>~s</code> and <code>~u</code> for you. Combine terms with
  <code>&amp;</code> (and), <code>|</code> (or), <code>!</code> (not) and parentheses.
</p>
<div class="note">
  <p>
    <strong>Not the same box as the row filter.</strong> <em>Filter rows</em>, above the
    table, only hides rows from view — it never stops or changes traffic. It takes plain
    text or a plain regular expression (<code>/api/</code>, <code>\.(png|jpg)</code>),
    matched against the whole row, not this <code>~</code> syntax.
  </p>
</div>

<table class="rules-table">
  <thead><tr><th>Filter</th><th>Matches</th><th>Example</th></tr></thead>
  <tbody>
    <tr><td><em>omitted</em></td><td>everything, both directions</td><td><code>|"EUR"|"USD"</code></td></tr>
    <tr><td><code>~q</code></td><td>requests only</td><td><code>|~q|secret|redacted</code></td></tr>
    <tr><td><code>~s</code></td><td>responses only</td><td><code>|~s|"ok":false|"ok":true</code></td></tr>
    <tr><td><code>~u</code> <em>regex</em></td><td>the URL matches</td><td><code>~u /api/v2/</code></td></tr>
    <tr><td><code>~d</code> <em>regex</em></td><td>the domain matches</td><td><code>~d staging\.example\.com</code></td></tr>
    <tr><td><code>~m</code> <em>method</em></td><td>request method</td><td><code>~m POST</code></td></tr>
    <tr><td><code>~t</code> <em>regex</em></td><td>content-type</td><td><code>~t json</code></td></tr>
    <tr><td><code>~c</code> <em>code</em></td><td>response status code</td><td><code>~c 500</code></td></tr>
    <tr><td><code>~hq</code> <em>regex</em></td><td>a request header matches</td><td><code>~hq Authorization</code></td></tr>
    <tr><td><code>~hs</code> <em>regex</em></td><td>a response header matches</td><td><code>~hs Set-Cookie</code></td></tr>
    <tr><td><code>~bq</code> <em>regex</em></td><td>the request body matches</td><td><code>~bq "checkout"</code></td></tr>
    <tr><td><code>~bs</code> <em>regex</em></td><td>the response body matches</td><td><code>~bs "error"</code></td></tr>
    <tr><td><code>~websocket</code></td><td>WebSocket flows</td><td><code>~websocket</code></td></tr>
    <tr><td><code>~all</code></td><td>everything, explicitly</td><td><code>~all</code></td></tr>
  </tbody>
</table>

<p>Combined:</p>
<pre>|~d staging\.example\.com &amp; ~m POST|"live":true|"live":false</pre>

<h3>Pattern symbols</h3>

<p>
  In the <strong>body</strong> box the pattern is a regular expression. If you only
  ever type plain text, it still works — plain text is a valid regex that matches
  itself. The symbols below are for when plain text is not enough.
</p>

<table class="rules-table">
  <thead><tr><th>Symbol</th><th>Means</th><th>Example</th><th>Matches</th></tr></thead>
  <tbody>
    <tr><td><code>.</code></td><td>any one character</td><td><code>a.c</code></td><td><code>abc</code>, <code>a1c</code></td></tr>
    <tr><td><code>*</code></td><td>zero or more of what came before</td><td><code>ab*</code></td><td><code>a</code>, <code>ab</code>, <code>abbb</code></td></tr>
    <tr><td><code>+</code></td><td>one or more</td><td><code>ab+</code></td><td><code>ab</code>, <code>abbb</code> — not <code>a</code></td></tr>
    <tr><td><code>?</code></td><td>zero or one (optional)</td><td><code>colou?r</code></td><td><code>color</code>, <code>colour</code></td></tr>
    <tr><td><code>\d</code></td><td>any digit</td><td><code>\d+</code></td><td><code>7</code>, <code>4200</code></td></tr>
    <tr><td><code>\w</code></td><td>letter, digit or underscore</td><td><code>\w+</code></td><td><code>user_42</code></td></tr>
    <tr><td><code>\s</code></td><td>any whitespace</td><td><code>:\s*</code></td><td><code>:</code>, <code>: </code>, <code>:&nbsp;&nbsp;&nbsp;</code></td></tr>
    <tr><td><code>[abc]</code></td><td>any one of these characters</td><td><code>[Tt]rue</code></td><td><code>True</code>, <code>true</code></td></tr>
    <tr><td><code>[^abc]</code></td><td>any character except these</td><td><code>"[^"]*"</code></td><td>a whole quoted string</td></tr>
    <tr><td><code>[0-9a-f]</code></td><td>a range</td><td><code>[0-9a-f]{6}</code></td><td><code>a3f0c1</code></td></tr>
    <tr><td><code>{n}</code></td><td>exactly n times</td><td><code>\d{4}</code></td><td><code>2026</code></td></tr>
    <tr><td><code>{n,m}</code></td><td>between n and m times</td><td><code>\d{2,4}</code></td><td><code>42</code>, <code>4200</code></td></tr>
    <tr><td><code>|</code></td><td>either side (alternation)</td><td><code>true|false</code></td><td><code>true</code>, <code>false</code></td></tr>
    <tr><td><code>( )</code></td><td>grouping</td><td><code>(ab)+</code></td><td><code>ab</code>, <code>ababab</code></td></tr>
    <tr><td><code>^</code></td><td>start of the body</td><td><code>^\{</code></td><td>a body that starts with <code>{</code></td></tr>
    <tr><td><code>$</code></td><td>end of the body</td><td><code>\}$</code></td><td>a body that ends with <code>}</code></td></tr>
    <tr><td><code>\</code></td><td>escape — take the next symbol literally</td><td><code>\.</code></td><td>a real dot, not "any character"</td></tr>
  </tbody>
</table>

<p>
  Characters that need escaping when you mean them literally:
  <code>. * + ? [ ] ( ) { } ^ $ |</code> and <code>\</code> itself. A dot inside a
  domain is the usual one — <code>~d api\.example\.com</code>.
</p>
<p>Two behaviours worth knowing:</p>
<ul>
  <li><strong>Every</strong> occurrence is replaced, not just the first.</li>
  <li><code>.</code> also matches newlines here, so <code>&lt;b&gt;.*&lt;/b&gt;</code> will span the lines of a pretty-printed body.</li>
</ul>

<h3>Header rules</h3>

<p>The headers box looks the same but behaves differently in three ways:</p>
<ul>
  <li>The pattern is a <strong>literal header name</strong>, not a regex — <code>Authorization</code>, not <code>Auth.*</code>.</li>
  <li>It <strong>replaces</strong> the header, or adds it when it was not there.</li>
  <li>An <strong>empty replacement deletes</strong> the header. That is the whole trick behind stripping auth.</li>
</ul>
<pre>|~q|X-Debug|1            add or overwrite a request header
|~q|Authorization|        delete the request's Authorization header
|~s|Cache-Control|no-store   force responses to be uncacheable</pre>

<h3>Examples</h3>

<p>Each row is what you type into the form's fields.</p>

<table class="rules-table">
  <thead><tr><th>You want</th><th>Kind</th><th>in</th><th>URL has</th><th>find</th><th>replace with</th></tr></thead>
  <tbody>
    <tr><td>Change a known value on API calls</td><td>body</td><td>requests</td><td><code>/api/</code></td><td><code>"amount":100</code></td><td><code>"amount":1</code></td></tr>
    <tr><td>Change <em>any</em> amount, whatever the number</td><td>body</td><td>requests</td><td><code>/api/</code></td><td><code>"amount":\d+</code></td><td><code>"amount":0</code></td></tr>
    <tr><td>Cope with unknown spacing</td><td>body</td><td>requests</td><td><code>/api/</code></td><td><code>"amount":\s*\d+</code></td><td><code>"amount":0</code></td></tr>
    <tr><td>Flip a feature flag in replies</td><td>body</td><td>replies</td><td>—</td><td><code>"enabled":false</code></td><td><code>"enabled":true</code></td></tr>
    <tr><td>Rewrite a form field</td><td>body</td><td>requests</td><td>—</td><td><code>qty=\d+</code></td><td><code>qty=999</code></td></tr>
    <tr><td>Swap a whole reply for a file</td><td>body</td><td>replies</td><td><code>/api/config</code></td><td><code>.*</code></td><td><code>@/tmp/mock.json</code></td></tr>
    <tr><td>Add a header to every request</td><td>header</td><td>requests</td><td>—</td><td><code>X-Debug</code></td><td><code>1</code></td></tr>
    <tr><td>Strip auth, to test the unauthenticated path</td><td>header</td><td>requests</td><td>—</td><td><code>Authorization</code></td><td>— <em>(empty removes it)</em></td></tr>
    <tr><td>Force replies to be uncacheable</td><td>header</td><td>replies</td><td>—</td><td><code>Cache-Control</code></td><td><code>no-store</code></td></tr>
    <tr><td>Only one host</td><td>advanced</td><td colspan="4"><code>|~d staging\.example\.com &amp; ~m POST|"live":true|"live":false</code></td></tr>
  </tbody>
</table>

<p>
  <code>@/path/to/file</code> in <em>replace with</em> loads the replacement from a file,
  which is how you swap a whole JSON reply. The file is read when you press
  <strong>Apply</strong>, so it has to exist already.
</p>

<h3>Traps</h3>

<table class="rules-table">
  <thead><tr><th>You write</th><th>What actually happens</th></tr></thead>
  <tbody>
    <tr>
      <td><code>\d</code> <code>\w</code> <code>\s</code></td>
      <td>Work as expected.</td>
    </tr>
    <tr>
      <td><code>\bword\b</code></td>
      <td>
        <strong>Not a word boundary.</strong> The pattern is unescaped as a string
        before it is compiled, so <code>\b</code> becomes a backspace byte. It will not
        match and nothing warns you. Match the surrounding characters instead, quotes
        included: <code>"word"</code>.
      </td>
    </tr>
    <tr>
      <td><code>\1</code> in a replacement</td>
      <td>
        <strong>Capture groups cannot be reused.</strong> <code>(\d+)</code> matches
        fine, but <code>\1</code> in the replacement inserts a raw byte, not the
        captured digits. Match around the part you want to keep rather than through it.
      </td>
    </tr>
    <tr>
      <td><code>\n</code> <code>\t</code></td>
      <td>Become a real newline or tab, which is usually what you wanted.</td>
    </tr>
    <tr>
      <td>A separator inside the pattern</td>
      <td>
        Only reachable in an <strong>advanced</strong> row — it splits the rule in the
        wrong place. The form picks a separator for you precisely so this cannot happen.
      </td>
    </tr>
  </tbody>
</table>

<h3>My rule did not fire</h3>

<ol>
  <li><strong>Nothing in <em>find</em>.</strong> A row with an empty find is skipped, and the panel says how many were.</li>
  <li><strong>Did you press Apply?</strong> Editing the fields arms nothing until you do.</li>
  <li><strong>Separator collision</strong>, in an <strong>advanced</strong> row only: does the filter or find text contain the character the line starts with?</li>
  <li><strong>Wrong direction.</strong> <code>~q</code> is requests, <code>~s</code> is responses. No filter means both.</li>
  <li><strong>The text is not what you assumed.</strong> Click the flow and read the real body. <code>"amount": 100</code> with a space does not match <code>"amount":100</code>.</li>
  <li><strong>Body over 5 MB.</strong> Large bodies are streamed rather than buffered, and a streamed body cannot be rewritten. The row shows a <code>streamed</code> tag.</li>
  <li><strong>A <code>\b</code> in the pattern.</strong> See Traps — it is a backspace here.</li>
  <li><strong>It was a replay.</strong> Repeated requests are marked as replays and pass through untouched.</li>
</ol>

<p class="hint">
  A rule that fails to parse is rejected outright and reported in the toolbar — it is
  never half-applied. The filter language and the rewriting are mitmproxy's own
  <code>modify_body</code> and <code>modify_headers</code>, so its documentation
  applies here too.
</p>
`;
