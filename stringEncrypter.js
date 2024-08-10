const crypto = require('crypto');
const readline = require('readline');

class StringEncrypter {
    static DESEDE_ENCRYPTION_SCHEME = 'des-ede3';
    static DES_ENCRYPTION_SCHEME = 'des';
    static DEFAULT_ENCRYPTION_KEY = 'Interamerican Software Solution & Integration Inc.';
    static UNICODE_FORMAT = 'utf8';

    constructor(encryptionScheme = StringEncrypter.DESEDE_ENCRYPTION_SCHEME, encryptionKey = StringEncrypter.DEFAULT_ENCRYPTION_KEY) {
        if (!encryptionKey || encryptionKey.trim().length < 24) {
            throw new Error('Encryption key must be at least 24 characters long');
        }

        this.encryptionScheme = encryptionScheme;
        this.encryptionKey = Buffer.alloc(encryptionScheme === StringEncrypter.DES_ENCRYPTION_SCHEME ? 8 : 24);
        this.encryptionKey.write(encryptionKey, StringEncrypter.UNICODE_FORMAT);
    }

    encrypt(unencryptedString) {
        if (!unencryptedString || unencryptedString.trim().length === 0) {
            throw new Error('Unencrypted string was null or empty');
        }

        const cipher = crypto.createCipheriv(this.encryptionScheme, this.encryptionKey, null);
        let encrypted = cipher.update(unencryptedString, StringEncrypter.UNICODE_FORMAT, 'base64');
        encrypted += cipher.final('base64');

        return encrypted;
    }

    decrypt(encryptedString) {
        if (!encryptedString || encryptedString.trim().length === 0) {
            throw new Error('Encrypted string was null or empty');
        }

        const decipher = crypto.createDecipheriv(this.encryptionScheme, this.encryptionKey, null);
        let decrypted = decipher.update(encryptedString, 'base64', StringEncrypter.UNICODE_FORMAT);
        decrypted += decipher.final(StringEncrypter.UNICODE_FORMAT);

        return decrypted;
    }
}

// Implementación de la interacción con el usuario usando readline
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const se = new StringEncrypter();

function promptUser() {
    rl.question('Options: [1] Encrypt, [2] Decrypt, [3] Exit. Choose the option: ', (option) => {
        if (option === '1') {
            rl.question('Enter word to encrypt: ', (stringToEncrypt) => {
                try {
                    const encryptedString = se.encrypt(stringToEncrypt);
                    console.log(`Encrypted String of "${stringToEncrypt}": ${encryptedString}`);
                } catch (error) {
                    console.log(`Error: ${error.message}`);
                }
                askContinue();
            });
        } else if (option === '2') {
            rl.question('Enter word to decrypt: ', (stringToDecrypt) => {
                try {
                    const decryptedString = se.decrypt(stringToDecrypt);
                    console.log(`Decrypted String of "${stringToDecrypt}" is: ${decryptedString}`);
                } catch (error) {
                    console.log(`Error: ${error.message}`);
                }
                askContinue();
            });
        } else if (option === '3') {
            rl.close();
        } else {
            console.log('Invalid Option!');
            askContinue();
        }
    });
}

function askContinue() {
    rl.question('Do you want to continue (Y=Yes, Any Value=No)? ', (again) => {
        if (again.toLowerCase() === 'y') {
            promptUser();
        } else {
            rl.close();
        }
    });
}

// Start the user interaction
promptUser();
