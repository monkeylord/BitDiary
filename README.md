# BitDiary
BitDiary Protocol and SDK, for developers. 

## Usage

### Install

Nodejs

~~~shell
npm install bitdiary
~~~

~~~ javascript
var BitDiary = require('bitdiary')
~~~

Browser

~~~html
<script src="https://unpkg.com/bitdiary/bitdiary.min.js"></script>
~~~

### Init Diary

~~~javascript
var diary = new BitDiary("Diary Private Key")
~~~

### New/Update Diary

~~~javascript
//var diaryEditKey = bsv.PrivateKey("Your Private Key")
var diaryEditKey = diary.newEditKey
var output = diary.getDiaryUpdateOutput("My Diary content", diaryEditKey)

/*
var tx = bsv.Transaction()
tx.addOutput(output)
tx.from(utxo)
....
tx.sign("UTXO Private Key")
*/

/*
moneyButton.render(MBDiv, {
    label: "Submit",
    ...,
    outputs: [{
        amount: output.satoshis / 100000000,
        script: output.script.toASM(),
        currency: 'BSV'
	},...]
})
*/

/*
// Sync
diary.readDiaries()
*/
~~~

### Read Diaries

~~~javascript
diary.readDiaries()
~~~

Or, read a single independent diary entry

~~~javascript
//var diaryViewKey = bsv.PrivateKey().publcKey
var diaryIndex = 0
var diaryViewKey = diary.EditKey(diaryIndex).publicKey

diary.readDiary(diaryViewKey)
~~~

## Protocol

BitDiary use Bitcoin Data Protocol pattern, and is pure OP_RETURN protocol.

Data is indexed by public key, encrypted by public key and signed by public key, so that you can find/decrypt/verify the data only if you have the public key.

The public key is derived from master key and is not used on blockchain. So the owner can have his privacy because no one knows the public key, or share diary entry with others by sharing public key.

Protocol structure is:

~~~
(OP_FALSE) OP_RETURN <Cryptic Prefix> <Encrypted Data> <Signature of plaintext Data>
~~~

#### CrypticPrefix

`CrypticPrefix` = Base64( Sha256( `APP Prefix` | `PublicKey Hex` ) )

#### Encrypted Data

`KeyBuffer` = Sha256( `PublicKey Hex` )

`Key` = `KeyBuffer`.slice(0,8)

`IV` = `KeyBuffer`.slice(8,16)

`Encrypted Data` = AES128CBCPKCS7( `plaintext Data` , `Key`, `IV`)

#### Signature

`Signature` = Base64( Secp256k1 Signature( `plaintext Data`, Sha256, `Private Key` ) )

## Implement

It's important to have unused public key to protect privacy.

BitDiary use Method 42 to derive sub keys. However, BIP32(HD) is OK.

### Key Derivation

BitDiary SDK use a bitcoin private key as `master key`.

BitDiary `index` diaries from `0` to `n`.

The diary entry's key is derived by Sha256Sha256(`master key`.childKey(String(`index`))) .

The reason why use sha256sha256 is to prevent retrieving `master key` from subkey.

### Diaries Organize

BitDiary organize diaries from oldest to newest by `0` to `n`.

BitDiary SDK use binary algorithm to sync diaries.

The reason why use binary algorithm is to find `n` as soon as possible, so that new diary can be pushed without waiting for all diaries synced.  

The basic search algorithm is 

~~~
flag_foundN = false
index_lastValid = -1
index_lastInvalid = -1
index_current = 0

while(!flag_foundN){
	// check if current index valid
	if(valid(fetchDiary(index_current))){
		index_lastValid = index_current
	}else{
		index_lastInvalid = index_current
	}
	
	// next index to check
	if(index_lastInvalid != -1){
		flag_foundN = (index_lastValid == index_lastInvalid - 1)
		index_current = index_lastInvalid + (index_lastInvalid - index_lastValid) / 2
	}else{
		index_current = (index_current + 1) * 2 - 1
	}
}

n = index_lastValid

// fetch all diaries
for(i=n; i>-1; i--)fetchDiary(i)

~~~





