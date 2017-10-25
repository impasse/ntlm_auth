const struct = require('python-struct');

const INITIATOR_ADDTYPE = 'initiator_addtype';
const INITIATOR_ADDRESS_LENGTH = 'initiator_address_length';
const ACCEPTOR_ADDRTYPE = 'acceptor_addrtype';
const ACCEPTOR_ADDRESS_LENGTH = 'acceptor_address_length';
const APPLICATION_DATA_LENGTH = 'application_data_length';
const INITIATOR_ADDRESS = 'initiator_address';
const ACCEPTOR_ADDRESS = 'acceptor_address';
const APPLICATION_DATA = 'application_data';

class GssChannelBindingsStruct {
    constructor() {
        Object.assign(this, {
            [INITIATOR_ADDTYPE]: 0,
            [INITIATOR_ADDRESS_LENGTH]: 0,
            [ACCEPTOR_ADDRTYPE]: 0,
            [ACCEPTOR_ADDRESS_LENGTH]: 0,
            [APPLICATION_DATA_LENGTH]: 0,
            [INITIATOR_ADDRESS]: Buffer.alloc(0),
            [ACCEPTOR_ADDRESS]: Buffer.alloc(0),
            [APPLICATION_DATA]: Buffer.alloc(0),
        });
    }

    get_data() {
        this[INITIATOR_ADDRESS_LENGTH] = this[INITIATOR_ADDRESS].length;
        this[ACCEPTOR_ADDRESS_LENGTH] = this[ACCEPTOR_ADDRESS].length;
        this[APPLICATION_DATA_LENGTH] = this[APPLICATION_DATA].length;
        return Buffer.concat([
            struct.pack('<L', this[INITIATOR_ADDTYPE]),
            struct.pack('<L', this[INITIATOR_ADDRESS_LENGTH]),
            this[INITIATOR_ADDRESS],
            struct.pack('<L', this[ACCEPTOR_ADDRTYPE]),
            struct.pack('<L', this[ACCEPTOR_ADDRESS_LENGTH]),
            this[ACCEPTOR_ADDRESS],
            struct.pack('<L', this[APPLICATION_DATA_LENGTH]),
            this[APPLICATION_DATA],
        ]);
    }
}

Object.assign(GssChannelBindingsStruct.prototype, {
    INITIATOR_ADDTYPE,
    INITIATOR_ADDRESS_LENGTH,
    ACCEPTOR_ADDRTYPE,
    ACCEPTOR_ADDRESS_LENGTH,
    APPLICATION_DATA_LENGTH,
    INITIATOR_ADDRESS,
    ACCEPTOR_ADDRESS,
    APPLICATION_DATA,
});

module.exports = GssChannelBindingsStruct;