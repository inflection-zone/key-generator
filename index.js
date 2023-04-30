const uuidAPIKey = require('uuid-apikey');
const generator = require('generate-password');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');


function encrypt(str) {
    const algorithm = 'aes-256-ctr';
    const LENGTH = 16;
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, Buffer.from('FoCKvdLslUuB4y3EZlKate7XGottHski1LmyqJHvUhs=', 'base64'), iv);
    let encrypted = cipher.update(str);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
};

function decrypt(str) {
    const algorithm = 'aes-256-ctr';
    const tokens = str.split(':');
    const iv = Buffer.from(tokens.shift(), 'hex');
    const encryptedText = Buffer.from(tokens.join(':'), 'hex');
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from('FoCKvdLslUuB4y3EZlKate7XGottHski1LmyqJHvUhs=', 'base64'), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
};

var ak = uuidAPIKey.create();

console.log('api-key------------ : ' + ak.apiKey + '\n');
console.log('UUID--------------- : ' + ak.uuid + '\n');

const password = generator.generate({
    length    : 12,
    numbers   : true,
    lowercase : true,
    uppercase : true,
    symbols   : false,
    exclude   : ',-@#$%^&*()',
});
console.log('password----------- : ' + password + '\n');

var salt = bcrypt.genSaltSync(32);
console.log('salt--------------- : ' + salt+ '\n');

var secret_key = crypto.randomBytes(128).toString('hex');
console.log('access-token-secret-128: ' + secret_key+ '\n');

var secret_key_32_hex = crypto.randomBytes(32).toString('hex');
console.log('access-token-secret-32-hex: ' + secret_key_32_hex+ '\n');

var secret_key_32_base64 = crypto.randomBytes(32).toString('base64');
console.log('access-token-secret-32-base64: ' + secret_key_32_base64+ '\n');

var secret_key_64 = crypto.randomBytes(64).toString('hex');
console.log('access-token-secret-64: ' + secret_key_64+ '\n');

var name = "Kiran Kharade";
var encrypted = encrypt(name);
console.log(encrypted);

var decrypted = decrypt(encrypted);
console.log(decrypted);

