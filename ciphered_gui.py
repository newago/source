import cryptography
import serpent



class CipheredGUI(BasicGUI):#héritage de la classe BasicGui
    def __init__(self, *args, **kwargs): #surcharge du constructeur de la classe BasicGUI
        super().__init__(*args, **kwargs)#constructeur par défaut de la classe parent
        self._key = kwargs.get("cle", None) #permet de stocker une clé de chiffrement

    def _create_connection_window(self):#permet de rajouter un champ pour le mot de passe lors de la connexion au chat
        super()._create_connection_window()
        self._connection_window.add_label("Password")
        self._connection_window.add_input("password")

    def run_chat(self):
        self._connection_window.run()
        password = self._connection_window.get_input("password")
        salt = b"r25y6xp0" # constante prise en entrée lors de la dérivation de la clé de chriffrement. Cela permet de rendre plus difficile les attaques brute force
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),#on crée la fonction de dérivation de la clé. On utilise le sel et on fait 10000 itérations pour sécuriser un maximum
                         length=16,
                         salt=salt,
                         iterations=100000,
                         backend=default_backend())
        self._key = kdf.derive(password.encode("utf8"))#on dérive la clé en utilisant le hachage SHA256
        super().run_chat()#on lance le chat

    def encrypt(self, plaintext):#cette fonction va permettre de chiffrer le texte grâce à notre clé de chiffrement
        iv = os.urandom(16) # on génère un vecteur d'initialisation aléatoire
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv), backend=default_backend())#On chiffre avec notre clé
        encryptor = cipher.encryptor()#on crée un outil à partir de cipher utilisé pour chiffrer les données
        padder = padding.PKCS7(128).padder()#on fait du padding pour avoir un message codé sur 128 bits pour l'AES
        padded_plaintext = padder.update(plaintext.encode("utf8")) + padder.finalize()
        encrypted = encryptor.update(padded_plaintext) + encryptor.finalize()
        return iv, encrypted #on revoie le résultat (vecteur d'initialisation et message chiffré)

    def decrypt(self, ciphertext):#on déchiffre un texte grâce à la clé et au vecteur d'initialisation. Ici, le paramètre ciphertext reçu correspond au retour de la fonction encrypt
        iv, encrypted = ciphertext#on sépare le vecteur d'initialisation et le texte chiffré
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv), backend=default_backend())#on crée une instance pour pouvoir déchiffrer sur le même modèle que le chiffrement
        decryptor = cipher.decryptor()#on déchiffre le message et on le stocke dans decrypted_padded_plaintext
        decrypted_padded_plaintext = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()#on retire la partie de passing
        unpadded_plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()
        return unpadded_plaintext.decode("utf8")#on renvoie le texte

    def send(self, message):#permet l'envoi du message en le chiffrant
        iv, encrypted = self.encrypt(message)
        super().send(serpent.dumps({"data": encrypted, "encoding": "raw"}), iv=iv)

    def recv(self):#permet la reception en déchiffrant le message
        message_dict = serpent.loads(super().recv())
        return self.decrypt((message_dict["iv"], message_dict["data"]))
    #la bibliothèque serpent permet de convertir les objets transmis sous un format qui ne peut pas être lu par d'autres programmes que python, ce qui empêche des modifications.
