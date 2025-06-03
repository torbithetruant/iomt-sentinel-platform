import threading
import time
import fed_detection  # Module contenant le FL (ton fl_loop)
import simulator_base  # Module contenant la boucle principale (simulate)

if __name__ == "__main__":
    # Lancer le thread FL
    fl_thread = threading.Thread(target=fed_detection.fl_loop, daemon=True)
    fl_thread.start()

    # Lancer le simulateur
    simulator_base.simulate()  # Cette boucle tourne "forever"
