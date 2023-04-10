# Alati za upravljanje zaporkama i prijavu

Ovi programi pisani su u programskom jeziku ```python``` te je za implementaciju kriptografskih funkcija korišten python paket ```pycryptodome``` https://pycryptodome.readthedocs.io/en/latest/src/introduction.html i moduli: ```Crypto.Hash```, ```Crypto.Random```, ```Crypto.Cipher```, ```Crypto.Protocol```. Pokreću se iz komandne linije uz ključne riječi i dodatne proizvoljne argumente.

## Mogućnosti programa usermgmt:
- dodavanje novog korisnika ```add```
- promjena lozinke postojećem korisniku ```passwd```
- brisanje korisnika ```del```
- forsiranje promjene lozinke pri sljedećem loginu ```forcepass```

## Organizacija baze

Baza podataka ima sljedeće tablice i podatke:

```TABLE passwords(username VARCHAR, password VARCHAR, salt VARCHAR, change_pass INTEGER)```

```TABLE master_password(master_password VARCHAR, salt VARCHAR)```

## Kriptiranje korisnika u bazi podataka aplikacije

User manager sve podatke zapisuje u bazu podataka. Pri svakom dohvatu/spremanju podataka stvara se simetrični ključ. dijelovi potrebni za generiranje ključa su masterPassword i random salt. MasterPassword je definiran u aplikaciji te spremljen u bazu podataka. Salt je random generirana vrijednost koja je uvijek jedinstvena. Nju je također potrebno negdje spremiti jer je potrebna za dekripciju. 

- prilikom enkripcije funkcija ```encrypt()``` samostalno generira ```nonce``` (najčešće informacija od 16 bajtova) koja služi kao dodatna metoda zaštite i jednokratno se koristi. ```nonce``` je potreban i za dekripciju pa ga je potrebno sačuvati. Stoga se prefiksira na šifrat lozinke te se zatim enkodira ```base64``` enkoderom i sprema u bazu. Prilikom dešifriranja lako se ponovno ekstrahira (prvih 16 bajtova).


## Pohrana/update para username-zaporka

Komanda za pohranu nove i update postojeće zaporke je sljedeća: ```./usermgmt add {username}``` te ```./usermgmt passwd {username}```

- napravi se SHA suma danog usernamea te se u bazi pokuša pronaći redak u kojem se nalazi
- ako redak **ne** postoji, stvorit će se novi zapis i spremiti se istim postupkom kao i kod updatea, a on je opisan u nastavku
- generira se `salt` vrijednost te ključ za simetričnu enkripciju

```salt = get_random_bytes(16)```
```key = PBKDF2(master_pass.strip(), salt, 32, count=1000, hmac_hash_module=SHA512)```

- prije enkripcije konkateniraju se dvije stvari: ```address_sha``` : ```password``` koji je prethodno nadopunjen sa _zero characterima_ ```password.rjust(256, '\0')```. Nadopunjen je do 256 znakova zato što je to uvjet zadatka.
- prethodni korak je potreban kako bi se kod dohvata lozinke mogao provjeriti **integritet**, tj. da napadač nije slučajno izmiješao retke u bazi i da smo sigurni da je ta lozinka koja nam je vraćena baš ta koja pripada toj adresi.

```AES.encrypt(address_sha+password)```

- prilikom enkripcije funkcija ```encrypt()``` samostalno generira ```nonce``` (najčešće informacija od 16 bajtova) koja služi kao dodatna metoda zaštite i jednokratno se koristi. ```nonce``` je potreban i za dekripciju pa ga je potrebno sačuvati. Stoga se prefiksira na šifrat lozinke te se zatim sve enkodira ```base64``` enkoderom i sprema u bazu. Prilikom dešifriranja passworda lako se ponovno ekstrahira (prvih 16 bajtova).


## Program za login

Komanda za login korisnika je:```./login {username}```

Prilikom logina provode se sljedeći koraci:
- računanje SHA sume danog korisničkog imena

```username_sha = SHA256.new(data=bytes(address, 'utf-8')).digest()```

- dohvat usera iz baze (jer su u bazi korisnici spremljene kao SHA sume)
- generiranje simetričnog ključa pomoću dohvaćenog ```salta```

```key = PBKDF2(master_pass, decoded_salt, 32, count=1000, hmac_hash_module=SHA512)```
- dekriptiranje pomoću stvorenog ključa

## Sigurnosni zahtjevi
- sve lozinke su kriptirane prije spremanja u bazu
- napadač ne može saznati ništa o duljini lozinka
- pri unosu lozinke, unos nije vidljiv
- samo administrator može dodavati nove korisnike
