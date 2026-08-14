// The one thing every UI module needs and none of them should own: "something
// changed, draw again". Without it, table.js would have to import app.js for
// render() while app.js imports table.js for renderTable() -- a cycle that ES
// modules resolve by handing one side an undefined binding at call time.
//
// app.js registers the real renderer once; everyone else just asks for a frame.

let renderFn = () => {};

export function onRender(fn) {
  renderFn = fn;
}

export function refresh() {
  renderFn();
}
