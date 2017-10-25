const struct = require('python-struct');

const keys = new Map([
    ['MSV_AV_EOL', 0x00],
    ['MSV_AV_NB_COMPUTER_NAME', 0x01],
    ['MSV_AV_NB_DOMAIN_NAME', 0x02],
    ['MSV_AV_DNS_COMPUTER_NAME', 0x03],
    ['MSV_AV_DNS_DOMAIN_NAME', 0x04],
    ['MSV_AV_DNS_TREE_NAME', 0x05],
    ['MSV_AV_FLAGS', 0x06],
    ['MSV_AV_TIMESTAMP', 0x07],
    ['MSV_AV_SINGLE_HOST', 0x08],
    ['MSV_AV_TARGET_NAME', 0x09],
    ['MSV_AV_CHANNEL_BINDINGS', 0x0a],
])

class TargetInfo {
    constructor(data) {
        if (data) {
            let attribute_type = 0xff;
            while (attribute_type != TargetInfo.MSV_AV_EOL) {
                attribute_type = struct.unpack('<H', data.slice(0, struct.sizeOf('<H')))[0];
                data = data.slice(struct.sizeOf('<H'));
                length = struct.unpack('<H', data.slice(0, struct.sizeOf('<H')))[0];
                data = data.slice(struct.sizeOf('<H'));
                this[attribute_type] = [length, data.slice(0, length)];
                data = data.slice(length);
            }
        }
    }

    get_data() {
        if (TargetInfo.MSV_AV_EOL in this) {
            delete this[TargetInfo.MSV_AV_EOL];
        }
        data = [];
        for (const key in this) {
            if (!keys.has(key)) continue;
            data.push(struct.pack('<HH', key, this[key][0]));
            data.push(this[key][1]);
        }
        return Buffer.concat(data);
    }
}

for(const k of keys.keys()) {
    TargetInfo.prototype[k] = keys.get(k);
}

module.exports = TargetInfo;
