#!/usr/bin/env python3
import socket
import sys
import threading
import os

clock_lock = threading.Lock()
global_clock = 0

peer_lock = threading.Lock()
peers = {}

own_address = None
own_port = None
shared_dir = None

server_socket = None
running = True

def update_clock():
    global global_clock
    with clock_lock:
        global_clock += 1
        print("=> Atualizando relogio para", global_clock)
        return global_clock

def add_or_update_peer(peer_id, status):
    with peer_lock:
        if peer_id in peers:
            peers[peer_id]['status'] = status
        else:
            ip, port_str = peer_id.split(":")
            peers[peer_id] = {"address": ip, "port": int(port_str), "status": status}
        print("Atualizando peer", peer_id, "status", status)

def send_message(dest_ip, dest_port, msg, expect_response=False):
    """
    Retorna (success, response).
      - success: True se a conexao e envio foram bem-sucedidos, False caso contrario
      - response: string recebida (se expect_response=True) ou None
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((dest_ip, dest_port))
        sock.sendall(msg.encode())
        print('Encaminhando mensagem "{}" para {}:{}'.format(msg.strip(), dest_ip, dest_port))
        if expect_response:
            response = sock.recv(4096).decode()
            sock.close()
            return True, response
        else:
            sock.close()
            return True, None
    except Exception as e:
        print("Erro ao enviar mensagem para {}:{} -> {}".format(dest_ip, dest_port, e))
        return False, None

def handle_connection(conn, addr):
    try:
        data = conn.recv(4096).decode()
        if not data:
            conn.close()
            return
        data = data.strip()
        parts = data.split()
        if len(parts) < 3:
            conn.close()
            return
        origem = parts[0]
        msg_type = parts[2]
        args = parts[3:]
        update_clock()

        if msg_type == "HELLO":
            add_or_update_peer(origem, "ONLINE")

        elif msg_type == "GET_PEERS":
            with peer_lock:
                peer_list = [p for p in peers if p != origem]
            num_peers = len(peer_list)
            response = "{}:{} PEER_LIST {} ".format(own_address, own_port, num_peers)
            for p in peer_list:
                with peer_lock:
                    status = peers[p]['status']
                response += "{}:{}:{}:0 ".format(p.split(":")[0], p.split(":")[1], status)
            response = response.strip() + "\n"
            update_clock()
            conn.sendall(response.encode())

        elif msg_type in ("PEER_LIST", "PEERS_LIST"):
            if len(args) < 1:
                conn.close()
                return
            try:
                num = int(args[0])
            except:
                num = 0
            for i in range(1, len(args)):
                peer_info = args[i]
                parts_info = peer_info.split(":")
                if len(parts_info) >= 3:
                    peer_id_resp = parts_info[0] + ":" + parts_info[1]
                    status = parts_info[2]
                    add_or_update_peer(peer_id_resp, status)

        elif msg_type == "BYE":
            add_or_update_peer(origem, "OFFLINE")

        conn.close()
    except Exception as e:
        print("Erro ao tratar conexao:", e)
        conn.close()

def server_thread():
    global server_socket, running
    while running:
        try:
            conn, addr = server_socket.accept()
            t = threading.Thread(target=handle_connection, args=(conn, addr))
            t.daemon = True
            t.start()
        except Exception as e:
            if running:
                print("Erro no servidor:", e)

def menu():
    while True:
        print("\nEscolha um comando:")
        print("[1] Listar peers")
        print("[2] Obter peers")
        print("[3] Listar arquivos locais")
        print("[4] Buscar arquivos")
        print("[5] Exibir estatisticas")
        print("[6] Alterar tamanho de chunk")
        print("[9] Sair")
        choice = input("> ").strip()

        if choice == "1":
            with peer_lock:
                if not peers:
                    print("Nenhum peer conhecido.")
                    continue
                print("Lista de peers:")
                print("[0] voltar para o menu anterior")
                keys = list(peers.keys())
                for idx, key in enumerate(keys, start=1):
                    print("[{}] {} {} (clock: {})".format(idx, key, peers[key]['status'], global_clock))
            sub_choice = input("> ").strip()
            if sub_choice == "0":
                continue
            try:
                idx = int(sub_choice) - 1
                with peer_lock:
                    if idx < 0 or idx >= len(keys):
                        print("Opcao invalida.")
                        continue
                    peer_id = keys[idx]
                    dest = peers[peer_id]
                current_clock = update_clock()
                message = "{} {} HELLO\n".format("{}:{}".format(own_address, own_port), current_clock)
                success, _ = send_message(dest['address'], dest['port'], message, expect_response=False)
                if success:
                    add_or_update_peer(peer_id, "ONLINE")
                else:
                    add_or_update_peer(peer_id, "OFFLINE")
            except Exception as e:
                print("Erro:", e)

        elif choice == "2":
            with peer_lock:
                keys = list(peers.keys())
            for peer_id in keys:
                dest = peers[peer_id]
                current_clock = update_clock()
                message = "{} {} GET_PEERS\n".format("{}:{}".format(own_address, own_port), current_clock)
                success, response = send_message(dest['address'], dest['port'], message, expect_response=True)
                if success and response:
                    update_clock()
                    parts = response.strip().split()
                    if len(parts) >= 4 and parts[2] in ("PEER_LIST", "PEERS_LIST"):
                        try:
                            num = int(parts[3])
                        except:
                            num = 0
                        for i in range(4, len(parts)):
                            peer_info = parts[i]
                            parts_info = peer_info.split(":")
                            if len(parts_info) >= 3:
                                peer_id_resp = parts_info[0] + ":" + parts_info[1]
                                status = parts_info[2]
                                add_or_update_peer(peer_id_resp, status)
                    add_or_update_peer(peer_id, "ONLINE")
                else:
                    add_or_update_peer(peer_id, "OFFLINE")

        elif choice == "3":
            try:
                files = os.listdir(shared_dir)
                if files:
                    for f in files:
                        print(f)
                else:
                    print("Diretorio vazio.")
            except Exception as e:
                print("Erro ao listar arquivos:", e)

        elif choice == "4":
            print("Funcionalidade Buscar arquivos nao implementada na Parte 1.")

        elif choice == "5":
            print("Funcionalidade Exibir estatisticas nao implementada na Parte 1.")

        elif choice == "6":
            print("Funcionalidade Alterar tamanho de chunk nao implementada na Parte 1.")

        elif choice == "9":
            with peer_lock:
                keys = list(peers.keys())
            for peer_id in keys:
                dest = peers[peer_id]
                if dest['status'] == "ONLINE":
                    current_clock = update_clock()
                    message = "{} {} BYE\n".format("{}:{}".format(own_address, own_port), current_clock)
                    send_message(dest['address'], dest['port'], message, expect_response=False)
            print("Saindo...")
            global running
            running = False
            try:
                server_socket.close()
            except:
                pass
            sys.exit(0)
        else:
            print("Opcao invalida.")

def main():
    global own_address, own_port, shared_dir, server_socket

    if len(sys.argv) != 4:
        print("Uso: {} <endereco:porta> <vizinhos.txt> <diretorio_compartilhado>".format(sys.argv[0]))
        sys.exit(1)

    try:
        addr_port = sys.argv[1]
        own_address, port_str = addr_port.split(":")
        own_port = int(port_str)
    except Exception as e:
        print("Erro ao parsear endereco e porta:", e)
        sys.exit(1)

    vizinhos_file = sys.argv[2]
    try:
        with open(vizinhos_file, "r") as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line:
                add_or_update_peer(line, "OFFLINE")
                print("Adicionando novo peer", line, "status OFFLINE")
    except Exception as e:
        print("Erro ao ler arquivo de vizinhos:", e)
        sys.exit(1)

    shared_dir = sys.argv[3]
    if not os.path.isdir(shared_dir) or not os.access(shared_dir, os.R_OK):
        print("Diretorio compartilhado invalido ou nao legivel.")
        sys.exit(1)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((own_address, own_port))
        server_socket.listen(5)
    except Exception as e:
        print("Erro ao iniciar servidor:", e)
        sys.exit(1)
    print("Servidor iniciado em {}:{}".format(own_address, own_port))

    threading.Thread(target=server_thread, daemon=True).start()
    menu()

if __name__ == "__main__":
    main()
