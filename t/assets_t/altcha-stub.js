/* altcha stub bundle for t/29 - not the real widget.
   Deliberately ends without a trailing newline, and on a semicolon: utils.read_file()
   drops the last byte, so a page served through it would lose that ";" and this
   file would prove nothing. read_file_bytes() must hand back every byte. */
customElements.define("altcha-widget", class extends HTMLElement {});