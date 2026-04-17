import json
import hashlib
import secrets
import time
import hmac
import os
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Tuple

USERS_FILENAME = "users.json"
AUDIT_FILENAME = "auth.log"
HASH_ITERACIJAS = 100000

def tagadnejs_laiks() -> float:
    return time.time()

def ierakstit_audita_zurnalu(notikums: str, informacija: str):
    laiks = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open(AUDIT_FILENAME, "a", encoding="utf-8") as f:
        f.write(f"[{laiks}] {notikums}: {informacija}\n")

@dataclass
class Lietotajs:
    username: str
    salt: str
    password_hash: str
    created_at: float
    last_login: float = 0.0
    failed_attempts: int = 0
    locked_until: float = 0.0
    last_fail_ts: float = 0.0

    def ir_blokets(self, tagad: float) -> bool:
        return self.locked_until > tagad

    def uz_vardnicu(self) -> dict:
        return {
            "username": self.username,
            "salt": self.salt,
            "password_hash": self.password_hash,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "failed_attempts": self.failed_attempts,
            "locked_until": self.locked_until,
            "last_fail_ts": self.last_fail_ts
        }

    @staticmethod
    def no_vardnicas(dati: dict) -> 'Lietotajs':
        return Lietotajs(
            username=dati.get("username", ""),
            salt=dati.get("salt", ""),
            password_hash=dati.get("password_hash", ""),
            created_at=dati.get("created_at", 0.0),
            last_login=dati.get("last_login", 0.0),
            failed_attempts=dati.get("failed_attempts", 0),
            locked_until=dati.get("locked_until", 0.0),
            last_fail_ts=dati.get("last_fail_ts", 0.0)
        )

# JAUNĀ KODA DAĻA (LoginAttempt un funkcija)
@dataclass
class LoginAttempt:
    username: str
    timestamp: float
    success: bool

def get_recent_failed_attempts(attempts: List[LoginAttempt], hours: float = 24) -> List[LoginAttempt]:
    """Atgriež neveiksmīgos mēģinājumus pēdējo 'hours' stundu laikā."""
    tagad = time.time()
    robeza = tagad - (hours * 3600)
    return [m for m in attempts if not m.success and m.timestamp >= robeza]
# JAUNĀS DAĻAS BEIGAS

class Glabatuve:
    def __init__(self, faila_nosaukums: str = USERS_FILENAME):
        self.faila_nosaukums = faila_nosaukums

    def ieladet(self) -> List[Lietotajs]:
        if not os.path.exists(self.faila_nosaukums):
            return []
        try:
            with open(self.faila_nosaukums, "r", encoding="utf-8") as f:
                dati = json.load(f)
            return [Lietotajs.no_vardnicas(vienums) for vienums in dati]
        except (json.JSONDecodeError, IOError):
            return []

    def saglabat(self, lietotaji: List[Lietotajs]):
        with open(self.faila_nosaukums, "w", encoding="utf-8") as f:
            json.dump([l.uz_vardnicu() for l in lietotaji], f, indent=2, ensure_ascii=False)

class AutentifikacijasServiss:
    def __init__(self, glabatuve: Glabatuve):
        self.glabatuve = glabatuve
        self.lietotaji: Dict[str, Lietotajs] = {}
        self.meginajumi: List[LoginAttempt] = []
        self._ieladet_lietotajus()

    def _ieladet_lietotajus(self):
        lietotaju_saraksts = self.glabatuve.ieladet()
        self.lietotaji = {l.username: l for l in lietotaju_saraksts}

    def _saglabat_lietotajus(self):
        self.glabatuve.saglabat(list(self.lietotaji.values()))

    def _heshot_paroli(self, parole: str, salt: bytes) -> str:
        atslega = hashlib.pbkdf2_hmac('sha256', parole.encode('utf-8'), salt, HASH_ITERACIJAS)
        return atslega.hex()

    def _generet_salt(self) -> bytes:
        return secrets.token_bytes(16)

    def registret(self, username: str, parole: str) -> bool:
        username = username.strip()
        if not username or not parole:
            print("Lietotājvārds un parole nevar būt tukši.")
            return False

        if username in self.lietotaji:
            print("Lietotājs ar šādu vārdu jau eksistē.")
            return False

        salt = self._generet_salt()
        password_hash = self._heshot_paroli(parole, salt)
        jauns_lietotajs = Lietotajs(
            username=username,
            salt=salt.hex(),
            password_hash=password_hash,
            created_at=tagadnejs_laiks()
        )
        self.lietotaji[username] = jauns_lietotajs
        self._saglabat_lietotajus()
        ierakstit_audita_zurnalu("REGISTRACIJA", f"Lietotājs {username} reģistrēts.")
        print("Reģistrācija veiksmīga!")
        return True

    def _aprekinat_risku(self, lietotajs: Lietotajs, ievadita_parole: str, tagad: float, iepriekseja_neveiksme: float) -> Tuple[int, List[str]]:
        risks = 0
        iemesli = []

        risks += 20 * lietotajs.failed_attempts
        iemesli.append(f"{lietotajs.failed_attempts} neveiksmīgs(i) mēģinājums(i)")

        if len(ievadita_parole) < 6:
            risks += 25
            iemesli.append("īsa parole (<6 simboli)")

        if iepriekseja_neveiksme > 0 and (tagad - iepriekseja_neveiksme) < 10:
            risks += 15
            iemesli.append("ļoti ātrs mēģinājums (<10s)")

        return risks, iemesli

    def _risks_nezinamam(self, ievadita_parole: str) -> Tuple[int, List[str]]:
        risks = 40
        iemesli = ["nezināms lietotājs"]
        if len(ievadita_parole) < 6:
            risks += 25
            iemesli.append("īsa parole (<6 simboli)")
        return risks, iemesli

    def _blokesanas_ilgums(self, risks: int) -> int:
        if risks < 40:
            return 0
        elif risks < 80:
            return 30
        else:
            return 120

    def pieslegties(self, username: str, parole: str) -> bool:
        username = username.strip()
        tagad = tagadnejs_laiks()
        lietotajs = self.lietotaji.get(username)

        if lietotajs is None:
            risks, iemesli = self._risks_nezinamam(parole)
            blokets_ilgums = self._blokesanas_ilgums(risks)
            iemeslu_teksts = ", ".join(iemesli)
            print("Nepareizs lietotājvārds vai parole.")
            print(f"Risks: {risks} ({iemeslu_teksts}) -> Bloķēts: {blokets_ilgums}s (nav attiecināms, lietotājs nav atrasts)")
            ierakstit_audita_zurnalu("PIESLEGSANAS NEVEIKSME", f"Nezināms lietotājs '{username}', risks {risks}, iemesli: {iemeslu_teksts}")
            # Reģistrē neveiksmīgu mēģinājumu (nezināms lietotājs)
            self.meginajumi.append(LoginAttempt(username, tagad, False))
            if len(self.meginajumi) > 1000:
                self.meginajumi = self.meginajumi[-1000:]
            return False

        if lietotajs.ir_blokets(tagad):
            atlikusas_sekundes = int(lietotajs.locked_until - tagad)
            print(f"Konts ir bloķēts. Mēģini vēlreiz pēc {atlikusas_sekundes} sekundēm.")
            ierakstit_audita_zurnalu("PIESLEGSANAS BLOKETA", f"Lietotājs {username} mēģināja pieslēgties bloķēšanas laikā")
            # Bloķēšanas laikā mēģinājumu neierakstām kā "parastu neveiksmi", bet varam, ja vēlas
            return False

        salt = bytes.fromhex(lietotajs.salt)
        sagaidamais_hash = lietotajs.password_hash
        faktiskais_hash = self._heshot_paroli(parole, salt)

        if hmac.compare_digest(faktiskais_hash, sagaidamais_hash):
            lietotajs.last_login = tagad
            lietotajs.failed_attempts = 0
            lietotajs.locked_until = 0.0
            lietotajs.last_fail_ts = 0.0
            self._saglabat_lietotajus()
            ierakstit_audita_zurnalu("PIESLEGSANAS VEIKSMIGA", f"Lietotājs {username} pieslēdzās")
            print("Pieslēgšanās veiksmīga!")
            # Reģistrē veiksmīgu mēģinājumu
            self.meginajumi.append(LoginAttempt(username, tagad, True))
            if len(self.meginajumi) > 1000:
                self.meginajumi = self.meginajumi[-1000:]
            return True
        else:
            iepriekseja_neveiksme = lietotajs.last_fail_ts
            lietotajs.failed_attempts += 1
            lietotajs.last_fail_ts = tagad

            risks, iemesli = self._aprekinat_risku(lietotajs, parole, tagad, iepriekseja_neveiksme)
            blokets_ilgums = self._blokesanas_ilgums(risks)

            if blokets_ilgums > 0:
                lietotajs.locked_until = tagad + blokets_ilgums

            self._saglabat_lietotajus()

            iemeslu_teksts = ", ".join(iemesli)
            print("Nepareiza parole.")
            print(f"Risks: {risks} ({iemeslu_teksts}) -> Bloķēts: {blokets_ilgums}s")
            ierakstit_audita_zurnalu("PIESLEGSANAS NEVEIKSME", f"Lietotājs {username}, risks {risks}, iemesli: {iemeslu_teksts}")
            # Reģistrē neveiksmīgu mēģinājumu
            self.meginajumi.append(LoginAttempt(username, tagad, False))
            if len(self.meginajumi) > 1000:
                self.meginajumi = self.meginajumi[-1000:]
            return False

    def profils(self, username: str) -> Optional[Lietotajs]:
        return self.lietotaji.get(username)

def galvena_izvelne():
    glabatuve = Glabatuve()
    serviss = AutentifikacijasServiss(glabatuve)

    while True:
        print("\n=== Mini Pieslēgšanās Sistēma ===")
        print("1. Reģistrēties")
        print("2. Pieslēgties")
        print("3. Iziet")
        izvele = input("Izvēlies opciju: ").strip()

        if izvele == "1":
            username = input("Lietotājvārds: ").strip()
            parole = input("Parole: ").strip()
            serviss.registret(username, parole)

        elif izvele == "2":
            username = input("Lietotājvārds: ").strip()
            parole = input("Parole: ").strip()
            veiksme = serviss.pieslegties(username, parole)
            if veiksme:
                while True:
                    print("\n--- Lietotāja izvēlne ---")
                    print("1. Profila informācija")
                    print("2. Iziet (Atteikties)")
                    apaksizvele = input("Izvēlies: ").strip()
                    if apaksizvele == "1":
                        lietotajs = serviss.profils(username)
                        if lietotajs:
                            print("\n=== Profils ===")
                            print(f"Lietotājs: {lietotajs.username}")
                            print(f"Reģistrēts: {time.ctime(lietotajs.created_at)}")
                            if lietotajs.last_login:
                                print(f"Pēdējā veiksmīgā pieslēgšanās: {time.ctime(lietotajs.last_login)}")
                            else:
                                print("Pēdējā veiksmīgā pieslēgšanās: nekad")
                            print(f"Neveiksmīgi mēģinājumi: {lietotajs.failed_attempts}")
                            if lietotajs.locked_until > tagadnejs_laiks():
                                print(f"Bloķēts līdz: {time.ctime(lietotajs.locked_until)}")
                            else:
                                print("Bloķēts: nē")
                            if lietotajs.last_fail_ts:
                                print(f"Pēdējais neveiksmīgais mēģinājums: {time.ctime(lietotajs.last_fail_ts)}")
                            
                            # JAUNĀ DAĻA
                            pedejas_neveiksmes = get_recent_failed_attempts(serviss.meginajumi, hours=24)
                            manas_neveiksmes = [m for m in pedejas_neveiksmes if m.username == username]
                            if manas_neveiksmes:
                                print(f"\n📊 Pēdējo 24 stundu neveiksmīgie mēģinājumi (tikai Jūsu kontam): {len(manas_neveiksmes)}")
                                for m in manas_neveiksmes[-5:]:  # rāda pēdējos 5
                                    print(f"  - {time.ctime(m.timestamp)}")
                            else:
                                print("\n✅ Pēdējo 24 stundu laikā nav neveiksmīgu mēģinājumu Jūsu kontam.")
                            # JAUNĀS DAĻAS BEIGAS
                        else:
                            print("Profils nav atrasts (kļūda).")
                    elif apaksizvele == "2":
                        print("Atgriežamies galvenajā izvēlnē.")
                        break
                    else:
                        print("Nepareiza izvēle, mēģini vēlreiz.")
        elif izvele == "3":
            print("Programma beidz darbu.")
            break
        else:
            print("Nepareiza izvēle, mēģini vēlreiz.")

if __name__ == "__main__":
    galvena_izvelne()
