#!/usr/bin/env python3
import socket
import sys
import threading
import os

# Variaveis globais para o relogio e para os peers
clock_lock = threading.Lock()
global_clock = 0

peer_lock = threading.Lock()
# Dicionario de peers: chave = "ip:porta", valor = { "address": ip, "port": porta, "status": "ONLINE" ou "OFFLINE" }
peers = {}

# Dados do peer local
own_address = None
own_port = None
shared_dir = None

server_socket = None
running = True  # Controle do loop do servidor


def update_clock():
    """Incrementa o relogio global e exibe a atualizacao."""
    global global_clock
    with clock_lock:
        global_clock += 1
        print("=> Atualizando relogio para", global_clock)
        return global_clock


def add_or_update_peer(peer_id, status):
    """Adiciona ou atualiza um peer na lista, imprimindo a mensagem de atualizacao."""
    with peer_lock:
        if peer_id in peers:
            peers[peer_id]['status'] = status
        else:
            ip, port_str = peer_id.split(":")
            peers[peer_id] = {"address": ip, "port": int(port_str), "status": status}
        print("Atualizando peer", peer_id, "status", status)


def send_message(dest_ip, dest_port, msg, expect_response=False):
    """
    Abre uma conexao TCP com o destino, envia a mensagem e opcionalmente aguarda uma resposta.
    Retorna a resposta (se houver) ou None em caso de falha.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((dest_ip, dest_port))
        sock.sendall(msg.encode())
        print('Encaminhando mensagem "{}" para {}:{}'.format(msg.strip(), dest_ip, dest_port))
        if expect_response:
            response = sock.recv(4096).decode()
            sock.close()
            return response
        sock.close()
        return None
    except Exception as e:
        print("Erro ao enviar mensagem para {}:{} -> {}".format(dest_ip, dest_port, e))
        return None


def handle_connection(conn, addr):
    """
    Trata uma conexao recebida: le a mensagem, atualiza o relogio, interpreta o tipo e age de acordo.
    """
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
        update_clock()  # Atualiza o relogio ao receber a mensagem

        if msg_type == "HELLO":
            # Ao receber HELLO, adiciona ou atualiza o peer remetente para ONLINE
            add_or_update_peer(origem, "ONLINE")

        elif msg_type == "GET_PEERS":
            # Responde com uma mensagem PEER_LIST contendo os peers conhecidos (exceto o remetente)
            with peer_lock:
                peer_list = [p for p in peers.keys() if p != origem]
            num_peers = len(peer_list)
            response = "{}:{} PEER_LIST {} ".format(own_address, own_port, num_peers)
            for p in peer_list:
                with peer_lock:
                    status = peers[p]['status']
                # Cada peer no formato: <endereco>:<porta>:<status>:0
                response += "{}:{}:{}:0 ".format(p.split(":")[0], p.split(":")[1], status)
            response = response.strip() + "\n"
            update_clock()  # Atualiza o relogio antes de enviar a resposta
            conn.sendall(response.encode())

        elif msg_type == "PEER_LIST":
            # Processa a resposta do GET_PEERS e atualiza a lista de peers
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
            # Ao receber BYE, atualiza o status do remetente para OFFLINE
            add_or_update_peer(origem, "OFFLINE")
        conn.close()
    except Exception as e:
        print("Erro ao tratar conexao:", e)
        conn.close()


def server_thread():
    """Thread que aceita conexoes e cria novas threads para trata-las."""
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
    """Exibe o menu de comandos e trata a interacao com o usuario."""
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
                send_message(dest['address'], dest['port'], message, expect_response=False)
                add_or_update_peer(peer_id, "ONLINE")
            except Exception as e:
                print("Erro:", e)

        elif choice == "2":
            # Envia GET_PEERS para cada peer conhecido e processa as respostas
            with peer_lock:
                keys = list(peers.keys())
            for peer_id in keys:
                dest = peers[peer_id]
                current_clock = update_clock()
                message = "{} {} GET_PEERS\n".format("{}:{}".format(own_address, own_port), current_clock)
                response = send_message(dest['address'], dest['port'], message, expect_response=True)
                if response:
                    update_clock()  # Atualiza o relogio apos receber a resposta
                    parts = response.strip().split()
                    if len(parts) >= 4 and parts[2] == "PEER_LIST":
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
            # Lista os arquivos presentes no diretorio compartilhado
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
            # Envia BYE para todos os peers ONLINE e encerra o programa
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

    # Processa o endereco e porta do peer
    try:
        addr_port = sys.argv[1]
        own_address, port_str = addr_port.split(":")
        own_port = int(port_str)
    except Exception as e:
        print("Erro ao parsear endereco e porta:", e)
        sys.exit(1)

    # Le os peers do arquivo de vizinhos e adiciona com status OFFLINE
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

    # Valida o diretorio compartilhado
    shared_dir = sys.argv[3]
    if not os.path.isdir(shared_dir) or not os.access(shared_dir, os.R_OK):
        print("Diretorio compartilhado invalido ou nao legivel.")
        sys.exit(1)

    # Inicia o servidor TCP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((own_address, own_port))
        server_socket.listen(5)
    except Exception as e:
        print("Erro ao iniciar servidor:", e)
        sys.exit(1)
    print("Servidor iniciado em {}:{}".format(own_address, own_port))

    # Inicia a thread do servidor para aceitar conexoes
    threading.Thread(target=server_thread, daemon=True).start()

    # Inicia o menu de interacao com o usuario
    menu()


if __name__ == "__main__":
    main()
