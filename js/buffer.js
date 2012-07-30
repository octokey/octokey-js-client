/* Extend Forge's ByteBuffer type with methods that we need. */

/* Appends an RFC4251 binary "string" type to a byte buffer. */
forge.util.ByteBuffer.prototype.putBinaryString = function (str) {
    this.putInt32(str.length);
    this.putBytes(str);
};

/* Appends a RFC4251 "mpint" (multi-precision integer) type to a buffer. */
forge.util.ByteBuffer.prototype.putBignum = function (value) {
    var hex = value.toString(16);
    // The most significant bit of the first byte is interpreted as a sign bit.
    // Our numbers are always positive, therefore if that bit is set, we need
    // to insert a zero byte to make sure the number is interpreted correctly.
    if (hex[0] >= '8') {
        hex = '00' + hex;
    }
    this.putBinaryString(forge.util.hexToBytes(hex));
};

/* Pretty-printed hex dump of buffer contents, for debugging */
forge.util.ByteBuffer.prototype.toPrettyHex = function () {
    var lines = this.toHex().split(/([0-9a-f]{32})/), output = [];

    for (var line_num = 0; line_num < lines.length; line_num++) {
        var line = lines[line_num];
        if (line) {
            line = line.replace(/([0-9a-f]{4})/g, '$1 ');
            var offset = (line_num * 16).toString(16) + ': ';
            while (offset.length < 9) {
                offset = '0' + offset;
            }
            output.push(offset + line.trimRight());
        }
    }
    return output.join("\n");
};
