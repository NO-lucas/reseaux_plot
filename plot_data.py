import pyshark
import matplotlib.pyplot as plt

# Fichier 1
cap1 = pyshark.FileCapture('video_1min.pcapng')

# Fichier 2
cap2 = pyshark.FileCapture('vocal_1min.pcapng')

# Initialisation des listes
times1 = []
times2 = []
packet_count1 = []
packet_count2 = []

# Parcours des paquets pour le fichier 1
nb1 = 0
shift1 = cap1[0].sniff_time.timestamp()
for pkt in cap1:
    nb1 += len(pkt.layers)
    times1.append(float(pkt.sniff_time.timestamp()-shift1))
    packet_count1.append(nb1)
    


nb2 = 0
shift2 = cap2[0].sniff_time.timestamp()
# Parcours des paquets pour le fichier 2
for pkt in cap2:
    nb2 += len(pkt.layers)
    times2.append(float(pkt.sniff_time.timestamp())-shift2)
    packet_count2.append(nb2)
    

print(nb1)
print(nb2)

# Affichage du graphique
plt.plot(times1, packet_count1, label='Appel avec vidéo')
plt.plot(times2, packet_count2, label='Appel sans vidéo')
plt.xlabel('Temps (secondes)')
plt.ylabel('Nombre de paquets')
plt.title('Nombre de paquets échangés')
plt.legend()
plt.savefig("Nombre de paquets échangés.png")
plt.show()