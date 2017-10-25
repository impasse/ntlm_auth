const { Ntlm } = require('./index');


const ntlm = new Ntlm;
console.log(ntlm.create_negotiate_message('XIAOMI', 'PC'));