// The standalone rules reference. Trusted, first-party documentation from
// rules-doc.js -- the one place innerHTML is correct; captured traffic never
// passes through here.
import { RULES_DOC_HTML } from "./rules-doc.js";

document.querySelector("#doc-body").innerHTML = RULES_DOC_HTML;
