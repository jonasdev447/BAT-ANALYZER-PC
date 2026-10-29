# =====================================================
# BAT-ANALYZER PC — Sistema de Investigação Genealógica
# Desenvolvido por Jonas de Campos | DarkblueDev
# Tema: Batcomputador — Painel de Controle
# =====================================================

import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import hashlib
import secrets
import os
import shutil
from datetime import datetime


ARQUIVO_USUARIOS = "batanalyzer_usuarios.json"
ARQUIVO_PESSOAS = "batanalyzer_dados.json"
ARQUIVO_ARVORES = "batanalyzer_arvores.json"
PASTA_DOCUMENTOS = "batanalyzer_documentos"
PASTA_FOTOS = "batanalyzer_fotos"


def hash_senha(senha, salt=None):
    """Gera um hash PBKDF2 da senha com salt aleatório."""
    if salt is None:
        salt = secrets.token_hex(16)

    derivada = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        bytes.fromhex(salt),
        200_000
    )
    return salt, derivada.hex()


class BatAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("BAT-ANALYZER PC")
        self.root.geometry("700x560")
        self.root.minsize(650, 520)
        self.root.configure(bg="#050505")

        self.usuarios = {}
        self.pessoas = []
        self.usuario_logado = None
        self.entradas = {}
        self.arvores = {}
        self.perfil_arvore_atual = None
        self.carregar_usuarios()
        self.tela_login()

    # =================================================
    # UTILITÁRIOS DE INTERFACE
    # =================================================
    def limpar_tela(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def criar_label(self, parent, texto, **kwargs):
        return tk.Label(
            parent,
            text=texto,
            bg=kwargs.pop("bg", "#050505"),
            fg=kwargs.pop("fg", "#00ffcc"),
            font=kwargs.pop("font", ("Consolas", 10)),
            **kwargs
        )

    def criar_botao(self, parent, texto, comando, bg="#00332a",
                    fg="#00ffcc", width=24):
        return tk.Button(
            parent,
            text=texto,
            command=comando,
            bg=bg,
            fg=fg,
            activebackground="#005044",
            activeforeground="#ffffff",
            font=("Consolas", 10, "bold"),
            width=width,
            relief="flat",
            cursor="hand2",
            padx=8,
            pady=8
        )

    def validar_senha(self, senha):
        if len(senha) < 8:
            messagebox.showwarning(
                "SENHA FRACA",
                "A senha deve ter pelo menos 8 caracteres."
            )
            return False
        return True

    # =================================================
    # USUÁRIOS: CARREGAR E SALVAR
    # =================================================
    def carregar_usuarios(self):
        try:
            with open(ARQUIVO_USUARIOS, "r", encoding="utf-8") as arquivo:
                dados = json.load(arquivo)
                if not isinstance(dados, dict):
                    raise ValueError("Formato de usuários inválido.")
                self.usuarios = dados
        except FileNotFoundError:
            self.usuarios = {}
        except (json.JSONDecodeError, OSError, ValueError) as erro:
            messagebox.showerror(
                "ERRO AO CARREGAR USUÁRIOS",
                "Não foi possível ler o arquivo de usuários.\n"
                "Se o arquivo estiver corrompido, faça uma cópia antes "
                "de tentar corrigir.\n\n"
                f"Detalhes: {erro}"
            )
            self.usuarios = {}

    def salvar_usuarios(self):
        temporario = ARQUIVO_USUARIOS + ".tmp"
        try:
            with open(temporario, "w", encoding="utf-8") as arquivo:
                json.dump(self.usuarios, arquivo, ensure_ascii=False, indent=2)
            os.replace(temporario, ARQUIVO_USUARIOS)
            return True
        except OSError as erro:
            messagebox.showerror(
                "ERRO AO SALVAR",
                f"Não foi possível salvar os usuários:\n{erro}"
            )
            try:
                if os.path.exists(temporario):
                    os.remove(temporario)
            except OSError:
                pass
            return False

    # =================================================
    # TELA DE LOGIN
    # =================================================
    def tela_login(self):
        self.usuario_logado = None
        self.limpar_tela()

        self.criar_label(
            self.root, "🦇 BAT-ANALYZER PC",
            font=("Consolas", 22, "bold")
        ).pack(pady=(45, 5))

        self.criar_label(
            self.root, "SISTEMA DE INVESTIGAÇÃO GENEALÓGICA",
            font=("Consolas", 10), fg="#446666"
        ).pack(pady=5)

        frame = tk.Frame(self.root, bg="#0a0a0a", padx=30, pady=25)
        frame.pack(pady=25)

        self.criar_label(frame, "USUÁRIO:", bg="#0a0a0a").grid(
            row=0, column=0, sticky="w", pady=10, padx=(0, 12)
        )
        self.user_entry = tk.Entry(
            frame, font=("Consolas", 12), width=25,
            bg="#111111", fg="#ffffff", insertbackground="#00ffcc"
        )
        self.user_entry.grid(row=0, column=1, pady=10)
        self.user_entry.focus_set()

        self.criar_label(frame, "SENHA:", bg="#0a0a0a").grid(
            row=1, column=0, sticky="w", pady=10, padx=(0, 12)
        )
        self.senha_entry = tk.Entry(
            frame, font=("Consolas", 12), width=25, show="●",
            bg="#111111", fg="#ffffff", insertbackground="#00ffcc"
        )
        self.senha_entry.grid(row=1, column=1, pady=10)
        self.senha_entry.bind("<Return>", lambda event: self.verificar_login())

        self.criar_botao(
            frame, "ENTRAR NO SISTEMA", self.verificar_login,
            width=28
        ).grid(row=2, column=0, columnspan=2, pady=(20, 12))

        links = tk.Frame(self.root, bg="#050505")
        links.pack(pady=5)
        self.criar_botao(
            links, "CRIAR CONTA", self.tela_criar_conta,
            bg="#002b33", fg="#00ccff", width=18
        ).grid(row=0, column=0, padx=8)
        self.criar_botao(
            links, "REDEFINIR SENHA", self.tela_redefinir_senha,
            bg="#1a1a1a", fg="#00ccff", width=20
        ).grid(row=0, column=1, padx=8)

        self.criar_label(
            self.root,
            f"Sistema carregado — {datetime.now().strftime('%d/%m/%Y')}",
            font=("Consolas", 8), fg="#333333"
        ).pack(side="bottom", pady=10)

    def verificar_login(self):
        usuario = self.user_entry.get().strip()
        senha = self.senha_entry.get()

        registro = self.usuarios.get(usuario)
        if not registro:
            messagebox.showerror("ACESSO NEGADO", "Usuário ou senha incorretos!")
            return

        try:
            salt = registro["salt"]
            hash_armazenado = registro["senha_hash"]
            _, hash_digitado = hash_senha(senha, salt)
        except (KeyError, TypeError, ValueError):
            messagebox.showerror(
                "ERRO DE CONTA",
                "Os dados desta conta estão inválidos no arquivo de usuários."
            )
            return

        if secrets.compare_digest(hash_digitado, hash_armazenado):
            self.usuario_logado = usuario
            self.carregar_dados()
            self.carregar_arvores()
            self.tela_principal()
        else:
            messagebox.showerror("ACESSO NEGADO", "Usuário ou senha incorretos!")

    # =================================================
    # CRIAR CONTA
    # =================================================
    def tela_criar_conta(self):
        self.limpar_tela()
        self.criar_label(
            self.root, "🦇 CRIAR NOVA CONTA",
            font=("Consolas", 18, "bold")
        ).pack(pady=25)

        frame = tk.Frame(self.root, bg="#0a0a0a", padx=30, pady=25)
        frame.pack(pady=10)

        self.novo_usuario = tk.Entry(
            frame, font=("Consolas", 11), width=30,
            bg="#111111", fg="#ffffff", insertbackground="#00ffcc"
        )
        self.nova_senha = tk.Entry(
            frame, font=("Consolas", 11), width=30, show="●",
            bg="#111111", fg="#ffffff", insertbackground="#00ffcc"
        )
        self.confirmar_senha = tk.Entry(
            frame, font=("Consolas", 11), width=30, show="●",
            bg="#111111", fg="#ffffff", insertbackground="#00ffcc"
        )

        campos = [
            ("NOVO USUÁRIO:", self.novo_usuario),
            ("SENHA (8+ CARACTERES):", self.nova_senha),
            ("CONFIRMAR SENHA:", self.confirmar_senha)
        ]
        for linha, (rotulo, entrada) in enumerate(campos):
            self.criar_label(frame, rotulo, bg="#0a0a0a").grid(
                row=linha, column=0, sticky="w", padx=(0, 15), pady=12
            )
            entrada.grid(row=linha, column=1, pady=12)

        self.criar_botao(
            frame, "CRIAR CONTA", self.criar_conta,
            width=25
        ).grid(row=3, column=0, columnspan=2, pady=18)

        self.criar_botao(
            self.root, "← VOLTAR AO LOGIN", self.tela_login,
            bg="#222222", fg="#ffffff"
        ).pack(pady=8)

    def criar_conta(self):
        usuario = self.novo_usuario.get().strip()
        senha = self.nova_senha.get()
        confirmacao = self.confirmar_senha.get()

        if not usuario:
            messagebox.showwarning("CAMPO OBRIGATÓRIO", "Digite um nome de usuário.")
            return
        if len(usuario) > 40 or any(c.isspace() for c in usuario):
            messagebox.showwarning(
                "USUÁRIO INVÁLIDO",
                "Use até 40 caracteres e não utilize espaços no usuário."
            )
            return
        if usuario in self.usuarios:
            messagebox.showwarning("USUÁRIO EXISTENTE", "Esse usuário já está cadastrado.")
            return
        if not self.validar_senha(senha):
            return
        if senha != confirmacao:
            messagebox.showwarning("SENHAS DIFERENTES", "As senhas não coincidem.")
            return

        codigo_recuperacao = secrets.token_hex(4).upper()
        salt, senha_hash = hash_senha(senha)
        salt_rec, codigo_hash = hash_senha(codigo_recuperacao)

        self.usuarios[usuario] = {
            "salt": salt,
            "senha_hash": senha_hash,
            "salt_recuperacao": salt_rec,
            "codigo_recuperacao_hash": codigo_hash,
            "criado_em": datetime.now().isoformat(timespec="seconds")
        }

        if not self.salvar_usuarios():
            self.usuarios.pop(usuario, None)
            return

        messagebox.showinfo(
            "CONTA CRIADA",
            f"Conta '{usuario}' criada com sucesso!\n\n"
            f"SEU CÓDIGO DE RECUPERAÇÃO:\n{codigo_recuperacao}\n\n"
            "Guarde esse código em local seguro. Ele será necessário "
            "para redefinir a senha e não poderá ser exibido novamente."
        )
        self.tela_login()

    # =================================================
    # REDEFINIR SENHA
    # =================================================
    def tela_redefinir_senha(self):
        self.limpar_tela()
        self.criar_label(
            self.root, "🔑 REDEFINIR SENHA",
            font=("Consolas", 18, "bold")
        ).pack(pady=(25, 8))
        self.criar_label(
            self.root,
            "Informe o usuário, o código de recuperação e a nova senha.",
            fg="#668888", font=("Consolas", 9)
        ).pack(pady=5)

        frame = tk.Frame(self.root, bg="#0a0a0a", padx=25, pady=20)
        frame.pack(pady=15)

        self.rec_usuario = tk.Entry(
            frame, font=("Consolas", 11), width=30,
            bg="#111111", fg="#ffffff", insertbackground="#00ffcc"
        )
        self.rec_codigo = tk.Entry(
            frame, font=("Consolas", 11), width=30,
            bg="#111111", fg="#ffffff", insertbackground="#00ffcc"
        )
        self.rec_nova_senha = tk.Entry(
            frame, font=("Consolas", 11), width=30, show="●",
            bg="#111111", fg="#ffffff", insertbackground="#00ffcc"
        )
        self.rec_confirmar_senha = tk.Entry(
            frame, font=("Consolas", 11), width=30, show="●",
            bg="#111111", fg="#ffffff", insertbackground="#00ffcc"
        )

        campos = [
            ("USUÁRIO:", self.rec_usuario),
            ("CÓDIGO DE RECUPERAÇÃO:", self.rec_codigo),
            ("NOVA SENHA:", self.rec_nova_senha),
            ("CONFIRMAR SENHA:", self.rec_confirmar_senha)
        ]
        for linha, (rotulo, entrada) in enumerate(campos):
            self.criar_label(frame, rotulo, bg="#0a0a0a").grid(
                row=linha, column=0, sticky="w", padx=(0, 12), pady=10
            )
            entrada.grid(row=linha, column=1, pady=10)

        self.criar_botao(
            frame, "SALVAR NOVA SENHA", self.redefinir_senha,
            width=25
        ).grid(row=4, column=0, columnspan=2, pady=18)

        self.criar_botao(
            self.root, "← VOLTAR AO LOGIN", self.tela_login,
            bg="#222222", fg="#ffffff"
        ).pack(pady=5)

    def redefinir_senha(self):
        usuario = self.rec_usuario.get().strip()
        codigo = self.rec_codigo.get().strip().upper()
        nova_senha = self.rec_nova_senha.get()
        confirmacao = self.rec_confirmar_senha.get()

        registro = self.usuarios.get(usuario)
        if not registro:
            messagebox.showerror(
                "RECUPERAÇÃO FALHOU",
                "Usuário ou código de recuperação inválido."
            )
            return

        try:
            salt_rec = registro["salt_recuperacao"]
            hash_rec_armazenado = registro["codigo_recuperacao_hash"]
            _, hash_codigo_digitado = hash_senha(codigo, salt_rec)
        except (KeyError, TypeError, ValueError):
            messagebox.showerror(
                "RECUPERAÇÃO INDISPONÍVEL",
                "Esta conta não possui um código de recuperação válido."
            )
            return

        if not secrets.compare_digest(hash_codigo_digitado, hash_rec_armazenado):
            messagebox.showerror(
                "RECUPERAÇÃO FALHOU",
                "Usuário ou código de recuperação inválido."
            )
            return

        if not self.validar_senha(nova_senha):
            return
        if nova_senha != confirmacao:
            messagebox.showwarning("SENHAS DIFERENTES", "As senhas não coincidem.")
            return

        salt, senha_hash = hash_senha(nova_senha)
        registro["salt"] = salt
        registro["senha_hash"] = senha_hash

        if self.salvar_usuarios():
            messagebox.showinfo(
                "SENHA ALTERADA",
                "Sua senha foi redefinida com sucesso! Entre com a nova senha."
            )
            self.tela_login()

    # =================================================
    # TELA PRINCIPAL
    # =================================================
    def tela_principal(self):
        self.limpar_tela()

        self.criar_label(
            self.root, "🦇 BAT-ANALYZER PC — PAINEL PRINCIPAL",
            font=("Consolas", 17, "bold")
        ).pack(pady=20)

        self.criar_label(
            self.root,
            f"Operador: {self.usuario_logado} | "
            f"{datetime.now().strftime('%d/%m/%Y %H:%M')}",
            font=("Consolas", 9), fg="#444444"
        ).pack()

        tk.Frame(self.root, bg="#00ffcc", height=1, width=600).pack(pady=15)

        frame_opcoes = tk.Frame(self.root, bg="#050505")
        frame_opcoes.pack(pady=8)

        estilo = {
            "font": ("Consolas", 10, "bold"),
            "width": 38,
            "height": 2,
            "relief": "flat",
            "cursor": "hand2"
        }

        tk.Button(
            frame_opcoes, text="🌳 ÁRVORE GENEALÓGICA FAMILIAR",
            bg="#001f33", fg="#00aaff",
            command=self.tela_perfis_arvore,
            **estilo
        ).grid(row=0, column=0, pady=6)

        tk.Button(
            frame_opcoes, text="⚙️ CONFIGURAÇÕES",
            bg="#1a1a1a", fg="#aaaaaa",
            command=lambda: self.modulo_em_construcao("Configurações"),
            **estilo
        ).grid(row=1, column=0, pady=6)

        tk.Button(
            frame_opcoes, text="🚪 SAIR DA CONTA",
            bg="#220000", fg="#ff6666",
            command=self.tela_login, **estilo
        ).grid(row=2, column=0, pady=(12, 5))

        self.criar_label(
            self.root, f"{len(self.pessoas)} pessoa(s) cadastrada(s)",
            font=("Consolas", 9), fg="#336666"
        ).pack(side="bottom", pady=8)

    # =================================================
    # CADASTRO DE PESSOAS
    # =================================================
    def tela_cadastrar(self):
        self.limpar_tela()
        self.criar_label(
            self.root, "👤 CADASTRAR PESSOA",
            font=("Consolas", 16, "bold")
        ).pack(pady=12)

        self.criar_botao(
            self.root, "← VOLTAR", self.tela_principal,
            bg="#222222", fg="#ffffff", width=14
        ).pack(anchor="nw", padx=10, pady=4)

        frame = tk.Frame(self.root, bg="#0a0a0a", padx=25, pady=15)
        frame.pack(pady=8, fill="x", padx=20)

        campos = [
            ("Nome completo:", "nome"),
            ("Apelido:", "apelido"),
            ("Data de nascimento:", "nascimento"),
            ("Local / Cidade:", "local"),
            ("Parentesco com você:", "parentesco"),
            ("Tudo que sabe sobre ela:", "observacoes")
        ]

        self.entradas = {}
        for linha, (rotulo, chave) in enumerate(campos):
            self.criar_label(
                frame, rotulo, bg="#0a0a0a", fg="#88ccff"
            ).grid(row=linha, column=0, sticky="nw", pady=6)

            if chave == "observacoes":
                entrada = tk.Text(
                    frame, width=38, height=3, font=("Consolas", 10),
                    bg="#111111", fg="#ffffff", insertbackground="#00ffcc"
                )
            else:
                entrada = tk.Entry(
                    frame, font=("Consolas", 10), width=38,
                    bg="#111111", fg="#ffffff", insertbackground="#00ffcc"
                )

            entrada.grid(row=linha, column=1, pady=6, padx=10)
            self.entradas[chave] = entrada

        self.criar_botao(
            frame, "💾 SALVAR PESSOA", self.salvar_pessoa,
            width=25
        ).grid(row=len(campos), column=0, columnspan=2, pady=12)

    def salvar_pessoa(self):
        dados = {
            "nome": self.entradas["nome"].get().strip(),
            "apelido": self.entradas["apelido"].get().strip(),
            "nascimento": self.entradas["nascimento"].get().strip(),
            "local": self.entradas["local"].get().strip(),
            "parentesco": self.entradas["parentesco"].get().strip(),
            "observacoes": self.entradas["observacoes"].get("1.0", tk.END).strip(),
            "cadastrado_em": datetime.now().strftime("%d/%m/%Y %H:%M"),
            "cadastrado_por": self.usuario_logado
        }

        if not dados["nome"]:
            messagebox.showwarning("AVISO", "Digite o nome da pessoa!")
            return

        self.pessoas.append(dados)
        if self.salvar_dados():
            messagebox.showinfo(
                "SALVO", f"{dados['nome']} cadastrado com sucesso!"
            )
            self.tela_principal()
        else:
            self.pessoas.pop()

    def tela_listar_pessoas(self):
        self.limpar_tela()
        self.criar_label(
            self.root, "🔍 PESSOAS CADASTRADAS",
            font=("Consolas", 16, "bold")
        ).pack(pady=15)

        topo = tk.Frame(self.root, bg="#050505")
        topo.pack(fill="x", padx=20)
        self.criar_botao(
            topo, "← VOLTAR", self.tela_principal,
            bg="#222222", fg="#ffffff", width=12
        ).pack(side="left")

        busca = tk.Entry(
            topo, font=("Consolas", 11), width=30,
            bg="#111111", fg="#ffffff", insertbackground="#00ffcc"
        )
        busca.pack(side="left", padx=10, ipady=5)

        lista = tk.Listbox(
            self.root, bg="#0a0a0a", fg="#00ffcc",
            selectbackground="#005044", font=("Consolas", 10),
            width=80, height=18
        )
        lista.pack(fill="both", expand=True, padx=20, pady=15)

        def atualizar_lista(*_):
            lista.delete(0, tk.END)
            termo = busca.get().strip().casefold()
            for pessoa in self.pessoas:
                nome = pessoa.get("nome", "")
                local = pessoa.get("local", "")
                if termo in nome.casefold() or termo in local.casefold():
                    lista.insert(tk.END, f"{nome} | {pessoa.get('nascimento', '')} | {local}")

        busca.bind("<KeyRelease>", atualizar_lista)
        atualizar_lista()


    # =================================================
    # ÁRVORES GENEALÓGICAS — 3 PERFIS INDEPENDENTES
    # =================================================
    def carregar_arvores(self):
        try:
            with open(ARQUIVO_ARVORES, "r", encoding="utf-8") as arquivo:
                dados = json.load(arquivo)
                self.arvores = dados if isinstance(dados, dict) else {}
        except FileNotFoundError:
            self.arvores = {}
        except (json.JSONDecodeError, OSError, ValueError) as erro:
            messagebox.showerror(
                "ERRO AO CARREGAR ÁRVORES",
                f"Não foi possível carregar as árvores:\n{erro}"
            )
            self.arvores = {}

        self.arvores.setdefault(self.usuario_logado, {})
        for perfil in ("01", "02", "03"):
            self.arvores[self.usuario_logado].setdefault(perfil, [])

    def salvar_arvores(self):
        temporario = ARQUIVO_ARVORES + ".tmp"
        try:
            with open(temporario, "w", encoding="utf-8") as arquivo:
                json.dump(self.arvores, arquivo, ensure_ascii=False, indent=2)
            os.replace(temporario, ARQUIVO_ARVORES)
            return True
        except OSError as erro:
            messagebox.showerror("ERRO AO SALVAR", f"Falha ao salvar árvores:\n{erro}")
            try:
                if os.path.exists(temporario):
                    os.remove(temporario)
            except OSError:
                pass
            return False

    def pessoas_do_perfil(self):
        if not self.usuario_logado or not self.perfil_arvore_atual:
            return []
        return self.arvores.setdefault(self.usuario_logado, {}).setdefault(
            self.perfil_arvore_atual, []
        )

    @staticmethod
    def percentual_ancestral(geracao):
        """
        G1 = pessoa de referência (100%, não é ancestral).
        G2 = pais (50% por progenitor), G3 = avós (25%), ...
        G11 = décima geração ancestral (0,09765625% por ancestral).
        É uma média teórica, não um teste genético individual.
        """
        try:
            geracao = int(geracao)
        except (TypeError, ValueError):
            return None
        if geracao <= 1:
            return 100.0
        return 100.0 / (2 ** (geracao - 1))

    @staticmethod
    def formatar_percentual(valor):
        if valor is None:
            return "N"
        if valor >= 1:
            return f"{valor:.4f}".rstrip("0").rstrip(".") + "%"
        return f"{valor:.8f}".rstrip("0").rstrip(".") + "%"

    def tela_perfis_arvore(self):
        self.limpar_tela()
        self.criar_label(
            self.root, "🦇 BATCOMPUTADOR // ARQUIVOS GENEALÓGICOS",
            font=("Consolas", 16, "bold")
        ).pack(pady=(20, 5))
        self.criar_label(
            self.root, "SELECIONE UM DOS 3 PERFIS FAMILIARES",
            fg="#447777", font=("Consolas", 9)
        ).pack(pady=(0, 18))

        for perfil, descricao in (
            ("01", "PERFIL PRINCIPAL"),
            ("02", "PERFIL SECUNDÁRIO"),
            ("03", "PERFIL TERCIÁRIO")
        ):
            membros = self.arvores.get(self.usuario_logado, {}).get(perfil, [])
            frame = tk.Frame(self.root, bg="#0a1114", highlightbackground="#00665c",
                             highlightthickness=1, padx=12, pady=10)
            frame.pack(fill="x", padx=45, pady=7)
            tk.Label(
                frame, text=f"ARQUIVO {perfil}  //  {descricao}",
                bg="#0a1114", fg="#00ffcc", font=("Consolas", 11, "bold")
            ).pack(anchor="w")
            tk.Label(
                frame, text=f"{len(membros)} registro(s) genealógico(s)",
                bg="#0a1114", fg="#668888", font=("Consolas", 9)
            ).pack(anchor="w", pady=(3, 7))
            tk.Button(
                frame, text="ABRIR ÁRVORE  ➜",
                command=lambda p=perfil: self.abrir_arvore(p),
                bg="#00332a", fg="#00ffcc", activebackground="#005044",
                font=("Consolas", 10, "bold"), relief="flat", cursor="hand2",
                padx=12, pady=6
            ).pack(anchor="e")

        self.criar_botao(
            self.root, "← VOLTAR AO PAINEL", self.tela_principal,
            bg="#222222", fg="#ffffff", width=22
        ).pack(pady=12)

    def abrir_arvore(self, perfil):
        self.perfil_arvore_atual = perfil
        self.tela_arvore()

    def tela_arvore(self):
        self.limpar_tela()
        perfil = self.perfil_arvore_atual
        pessoas = self.pessoas_do_perfil()

        cabecalho = tk.Frame(self.root, bg="#050505")
        cabecalho.pack(fill="x", padx=12, pady=(10, 4))
        self.criar_label(
            cabecalho, f"🌳 ÁRVORE FAMILIAR // PERFIL {perfil}",
            font=("Consolas", 14, "bold")
        ).pack(side="left")
        self.criar_botao(
            cabecalho, "← PERFIS", self.tela_perfis_arvore,
            bg="#222222", fg="#ffffff", width=12
        ).pack(side="right")

        barra = tk.Frame(self.root, bg="#050505")
        barra.pack(fill="x", padx=12, pady=5)
        self.criar_botao(
            barra, "＋ ADICIONAR PESSOA", self.tela_form_pessoa_arvore,
            width=21
        ).pack(side="left", padx=(0, 6))
        self.criar_botao(
            barra, "📋 LISTA / DETALHES", self.tela_lista_arvore,
            bg="#002b33", fg="#00ccff", width=20
        ).pack(side="left")

        legenda = "G1: referência (100%) | G2: pais (50%) | ... | G11: 10ª geração ancestral (0,09765625%)"
        self.criar_label(self.root, legenda, fg="#447777", font=("Consolas", 8)).pack(pady=3)

        area = tk.Frame(self.root, bg="#080d10")
        area.pack(fill="both", expand=True, padx=12, pady=(3, 12))
        canvas = tk.Canvas(area, bg="#080d10", highlightthickness=1,
                           highlightbackground="#00443e", height=330)
        hbar = tk.Scrollbar(area, orient="horizontal", command=canvas.xview)
        vbar = tk.Scrollbar(area, orient="vertical", command=canvas.yview)
        canvas.configure(xscrollcommand=hbar.set, yscrollcommand=vbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")
        area.grid_rowconfigure(0, weight=1)
        area.grid_columnconfigure(0, weight=1)

        if not pessoas:
            canvas.create_text(
                300, 130, text="NENHUM REGISTRO NESTE ARQUIVO\n\n"
                "Use + ADICIONAR PESSOA para começar.",
                fill="#00aa99", font=("Consolas", 12), justify="center"
            )
            canvas.configure(scrollregion=(0, 0, 700, 300))
            return

        # Cartões organizados por geração, com ligações para pai/mãe.
        largura, altura, gap_x, gap_y = 175, 72, 25, 90
        x_inicio, y_inicio = 25, 35
        por_id = {p["id"]: p for p in pessoas}
        por_geracao = {}
        for pessoa in pessoas:
            geracao = max(1, min(11, int(pessoa.get("geracao", 1))))
            por_geracao.setdefault(geracao, []).append(pessoa)

        posicoes = {}
        geracao_maxima = max(
            (max(1, min(11, int(p.get("geracao", 1)))) for p in pessoas),
            default=1
        )

        # Primeiro posiciona a pessoa de referência (G1) na base.
        # Cada geração ancestral fica acima, sem deixar a árvore perdida
        # milhares de pixels abaixo quando ainda há poucas gerações.
        membros_base = por_geracao.get(1, [])
        for indice, pessoa in enumerate(membros_base):
            x = x_inicio + indice * (largura + gap_x)
            y = y_inicio + (geracao_maxima - 1) * (altura + gap_y)
            posicoes[pessoa["id"]] = (x, y)

        # Distribui ancestrais acima dos descendentes que os referenciam.
        # O centro horizontal de cada ancestral é calculado a partir dos filhos.
        for geracao in range(2, geracao_maxima + 1):
            membros = por_geracao.get(geracao, [])
            usados = set()
            for pessoa in membros:
                filhos = [
                    filho for filho in pessoas
                    if filho.get("pai_id") == pessoa["id"]
                    or filho.get("mae_id") == pessoa["id"]
                ]
                filhos_posicionados = [
                    posicoes[filho["id"]] for filho in filhos
                    if filho["id"] in posicoes
                ]
                if filhos_posicionados:
                    centro_filho = sum(x + largura / 2 for x, y in filhos_posicionados) / len(filhos_posicionados)
                    x = max(x_inicio, int(centro_filho - largura / 2))
                    usados.add(pessoa["id"])
                else:
                    x = x_inicio + len(posicoes) * (largura + gap_x)
                y = y_inicio + (geracao_maxima - geracao) * (altura + gap_y)
                posicoes[pessoa["id"]] = (x, y)

            # Evita sobreposição quando há ancestrais sem vínculo configurado.
            ocupados = []
            for pessoa in membros:
                x, y = posicoes[pessoa["id"]]
                if any(abs(x - ox) < largura + 10 for ox in ocupados):
                    x = max([ox + largura + gap_x for ox in ocupados] + [x_inicio])
                    posicoes[pessoa["id"]] = (x, y)
                ocupados.append(posicoes[pessoa["id"]][0])

        # Linhas desenhadas primeiro para ficarem atrás dos cartões.
        for pessoa in pessoas:
            x, y = posicoes[pessoa["id"]]
            for chave in ("pai_id", "mae_id"):
                id_pai = pessoa.get(chave)
                if id_pai in posicoes:
                    px, py = posicoes[id_pai]
                    canvas.create_line(
                        px + largura // 2, py + altura,
                        x + largura // 2, y,
                        fill="#007f72", width=2, arrow="last"
                    )

        for pessoa in pessoas:
            x, y = posicoes[pessoa["id"]]
            nome = f"{pessoa.get('nome', 'N')} {pessoa.get('sobrenome', 'N')}".strip()
            nome = nome if len(nome) <= 24 else nome[:21] + "..."
            status = pessoa.get("status", "N")
            cor = "#12302e" if status == "Viva" else "#292126" if status == "Morta" else "#152126"
            card = canvas.create_rectangle(
                x, y, x + largura, y + altura, fill=cor,
                outline="#00bfa5", width=2
            )
            titulo = canvas.create_text(
                x + largura/2, y + 21, text=nome,
                fill="#d9ffff", font=("Consolas", 9, "bold"), width=largura-12
            )
            subtitulo = canvas.create_text(
                x + largura/2, y + 49,
                text=f"G{pessoa.get('geracao', 1)} | {self.formatar_percentual(self.percentual_ancestral(pessoa.get('geracao', 1)))} | {status} | Nasc.: {pessoa.get('nascimento', 'N')}",
                fill="#70bdb4", font=("Consolas", 7), width=largura-8
            )
            for item in (card, titulo, subtitulo):
                canvas.tag_bind(item, "<Button-1>", lambda event, pid=pessoa["id"]: self.detalhes_pessoa_arvore(pid))
                canvas.tag_bind(item, "<Enter>", lambda event: canvas.configure(cursor="hand2"))
                canvas.tag_bind(item, "<Leave>", lambda event: canvas.configure(cursor=""))
        max_x = max((x for x, y in posicoes.values()), default=0) + largura + 40
        max_y = max((y for x, y in posicoes.values()), default=0) + altura + 40
        canvas.configure(scrollregion=(0, 0, max(700, max_x), max(330, max_y)))
        # A pessoa de referência (G1) fica na parte inferior, como em árvores
        # genealógicas tradicionais. Abrimos a visualização por baixo.
        canvas.update_idletasks()
        canvas.yview_moveto(1.0)

    def tela_form_pessoa_arvore(self, pessoa_id=None):
        pessoas = self.pessoas_do_perfil()
        existente = next((p for p in pessoas if p["id"] == pessoa_id), None) if pessoa_id else None
        self.limpar_tela()
        titulo = "EDITAR REGISTRO" if existente else "NOVO REGISTRO GENEALÓGICO"
        self.criar_label(self.root, f"🦇 {titulo}", font=("Consolas", 15, "bold")).pack(pady=10)
        self.criar_label(
            self.root, "Campos desconhecidos: digite N. G1 = referência; G2–G11 = pais até 10ª geração ancestral.",
            fg="#668888", font=("Consolas", 9)
        ).pack(pady=(0, 8))

        exterior = tk.Frame(self.root, bg="#050505")
        exterior.pack(fill="both", expand=True, padx=15, pady=5)
        form_canvas = tk.Canvas(exterior, bg="#050505", highlightthickness=0)
        scroll = tk.Scrollbar(exterior, orient="vertical", command=form_canvas.yview)
        interior = tk.Frame(form_canvas, bg="#0a0a0a", padx=15, pady=10)
        interior.bind("<Configure>", lambda e: form_canvas.configure(scrollregion=form_canvas.bbox("all")))
        form_canvas.create_window((0, 0), window=interior, anchor="nw")
        form_canvas.configure(yscrollcommand=scroll.set)
        form_canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        campos = [
            ("Nome", "nome"), ("Sobrenome", "sobrenome"), ("Apelido", "apelido"),
            ("Data de nascimento", "nascimento"), ("Idade", "idade"),
            ("Data de falecimento", "morte"), ("Terra / local de origem", "terra"),
            ("Geração (1 a 11; G1 = referência)", "geracao"), ("Status", "status"),
            ("Pai (opcional)", "pai_id"), ("Mãe (opcional)", "mae_id"),
            ("Biografia / história", "bio")
        ]
        self.form_arvore = {}
        self.form_valores = {}
        for linha, (rotulo, chave) in enumerate(campos):
            self.criar_label(interior, rotulo.upper() + ":", bg="#0a0a0a", fg="#88ccff").grid(
                row=linha, column=0, sticky="nw", padx=(0, 12), pady=5
            )
            valor = existente.get(chave, "N") if existente else ("1" if chave == "geracao" else "N")
            if chave == "status":
                widget = tk.StringVar(value=valor if valor in ("Viva", "Morta", "N") else "N")
                entrada = tk.OptionMenu(interior, widget, "Viva", "Morta", "N")
                entrada.config(bg="#111111", fg="#00ffcc", activebackground="#005044",
                               highlightthickness=0, width=25, font=("Consolas", 9))
                entrada["menu"].config(bg="#111111", fg="#00ffcc")
                self.form_valores[chave] = widget
            elif chave in ("pai_id", "mae_id"):
                opcoes = ["N"] + [
                    f"{p.get('nome','N')} {p.get('sobrenome','N')} [G{p.get('geracao',1)}] :: {p['id']}"
                    for p in pessoas if not existente or p["id"] != existente["id"]
                ]
                escolhido = "N"
                if valor != "N":
                    pai = next((p for p in pessoas if p["id"] == valor), None)
                    if pai:
                        escolhido = f"{pai.get('nome','N')} {pai.get('sobrenome','N')} [G{pai.get('geracao',1)}] :: {pai['id']}"
                widget = tk.StringVar(value=escolhido)
                entrada = tk.OptionMenu(interior, widget, *opcoes)
                entrada.config(bg="#111111", fg="#00ffcc", activebackground="#005044",
                               highlightthickness=0, width=30, font=("Consolas", 8))
                entrada["menu"].config(bg="#111111", fg="#00ffcc")
                self.form_valores[chave] = widget
            elif chave == "bio":
                entrada = tk.Text(interior, width=42, height=5, bg="#111111", fg="#ffffff",
                                  insertbackground="#00ffcc", font=("Consolas", 9))
                entrada.insert("1.0", valor if valor else "N")
            else:
                entrada = tk.Entry(interior, width=42, bg="#111111", fg="#ffffff",
                                   insertbackground="#00ffcc", font=("Consolas", 9))
                entrada.insert(0, str(valor))
            entrada.grid(row=linha, column=1, sticky="w", pady=5)
            self.form_arvore[chave] = entrada

        rodape = tk.Frame(self.root, bg="#050505")
        rodape.pack(pady=8)
        self.criar_botao(
            rodape, "💾 SALVAR", lambda: self.salvar_pessoa_arvore(pessoa_id),
            width=14
        ).pack(side="left", padx=5)
        self.criar_botao(
            rodape, "📎 DOCUMENTOS", lambda: self.tela_documentos_pessoa(
                pessoa_id if pessoa_id else None
            ),
            bg="#002b33", fg="#00ccff", width=16
        ).pack(side="left", padx=4)
        self.criar_botao(
            rodape, "🖼 FOTOS", lambda: self.tela_fotos_pessoa(
                pessoa_id if pessoa_id else None
            ),
            bg="#092820", fg="#00ff99", width=12
        ).pack(side="left", padx=4)
        self.criar_botao(
            rodape, "CANCELAR", self.tela_arvore,
            bg="#222222", fg="#ffffff", width=14
        ).pack(side="left", padx=5)

    def salvar_pessoa_arvore(self, pessoa_id=None):
        pessoas = self.pessoas_do_perfil()
        dados = {}
        for chave, widget in self.form_arvore.items():
            if chave == "bio":
                valor = widget.get("1.0", tk.END).strip() or "N"
            elif chave in ("status", "pai_id", "mae_id"):
                valor = self.form_valores[chave].get()
                if chave in ("pai_id", "mae_id") and "::" in valor:
                    valor = valor.rsplit("::", 1)[1].strip()
                elif chave in ("pai_id", "mae_id"):
                    valor = "N"
            else:
                valor = widget.get().strip() or "N"
            dados[chave] = valor

        try:
            geracao = int(dados["geracao"])
            if geracao < 1 or geracao > 11:
                raise ValueError
        except ValueError:
            messagebox.showwarning("GERAÇÃO INVÁLIDA", "Escolha uma geração de 1 até 11 (G1 é a pessoa de referência).")
            return
        if dados["nome"] == "N":
            messagebox.showwarning("NOME OBRIGATÓRIO", "Informe o nome ou digite N se for desconhecido.")
            return

        # Pai e mãe precisam estar numa geração anterior à da pessoa.
        por_id = {p["id"]: p for p in pessoas}
        for chave in ("pai_id", "mae_id"):
            id_pai = dados[chave]
            if id_pai != "N":
                pai = por_id.get(id_pai)
                if not pai:
                    messagebox.showwarning("PARENTE INVÁLIDO", "O pai/mãe selecionado não existe mais.")
                    return
                if int(pai.get("geracao", 1)) <= geracao:
                    messagebox.showwarning(
                        "GERAÇÃO INCOMPATÍVEL",
                        "Pai e mãe precisam estar em uma geração numericamente maior que a pessoa. "
                        "G1 é a pessoa de referência; G10 é a geração ancestral mais distante."
                    )
                    return
        dados["geracao"] = geracao
        dados["id"] = pessoa_id or secrets.token_hex(6)
        dados["atualizado_em"] = datetime.now().strftime("%d/%m/%Y %H:%M")

        anterior = next((p for p in pessoas if p["id"] == pessoa_id), None)
        if anterior:
            anterior.update(dados)
        else:
            pessoas.append(dados)

        if self.salvar_arvores():
            self.tela_arvore()
        elif not anterior:
            pessoas.pop()

    def tela_lista_arvore(self):
        pessoas = self.pessoas_do_perfil()
        self.limpar_tela()
        self.criar_label(
            self.root, f"📋 REGISTROS // PERFIL {self.perfil_arvore_atual}",
            font=("Consolas", 14, "bold")
        ).pack(pady=12)
        topo = tk.Frame(self.root, bg="#050505")
        topo.pack(fill="x", padx=12)
        self.criar_botao(topo, "← ÁRVORE", self.tela_arvore,
                         bg="#222222", fg="#ffffff", width=12).pack(side="left")
        self.criar_botao(topo, "＋ ADICIONAR", self.tela_form_pessoa_arvore,
                         width=15).pack(side="right")
        lista = tk.Listbox(self.root, bg="#0a0a0a", fg="#00ffcc",
                           selectbackground="#005044", font=("Consolas", 10), height=17)
        lista.pack(fill="both", expand=True, padx=15, pady=12)
        mapa = []
        for p in sorted(pessoas, key=lambda x: (int(x.get("geracao", 1)), x.get("nome", ""))):
            mapa.append(p["id"])
            lista.insert(tk.END, f"G{p.get('geracao', 1)} | {p.get('nome','N')} {p.get('sobrenome','N')} | {p.get('status','N')}")

        def abrir_selecionado(event=None):
            selecao = lista.curselection()
            if selecao:
                self.detalhes_pessoa_arvore(mapa[selecao[0]])
        lista.bind("<Double-Button-1>", abrir_selecionado)
        lista.bind("<Return>", abrir_selecionado)

    def detalhes_pessoa_arvore(self, pessoa_id):
        pessoa = next((p for p in self.pessoas_do_perfil() if p["id"] == pessoa_id), None)
        if not pessoa:
            return
        self.limpar_tela()
        self.criar_label(
            self.root, "🦇 DOSSIÊ GENEALÓGICO",
            font=("Consolas", 16, "bold")
        ).pack(pady=(15, 5))
        self.criar_label(
            self.root, f"ARQUIVO {self.perfil_arvore_atual} // ID {pessoa_id}",
            fg="#447777", font=("Consolas", 8)
        ).pack(pady=(0, 10))

        nome = f"{pessoa.get('nome','N')} {pessoa.get('sobrenome','N')}"
        status = pessoa.get("status", "N")
        cor_status = "#00ff99" if status == "Viva" else "#ff6677" if status == "Morta" else "#00ccff"

        # Foto principal: PNG funciona com Tkinter puro; JPG também é exibido
        # quando Pillow estiver instalado. A referência fica guardada para não sumir.
        caminho_foto = pessoa.get("foto_principal", "")
        if caminho_foto and os.path.isfile(caminho_foto):
            try:
                try:
                    from PIL import Image, ImageTk
                    imagem = Image.open(caminho_foto)
                    imagem.thumbnail((150, 150))
                    self._foto_principal_img = ImageTk.PhotoImage(imagem)
                except ImportError:
                    self._foto_principal_img = tk.PhotoImage(file=caminho_foto)
                    fator = max(
                        1,
                        (self._foto_principal_img.width() + 149) // 150,
                        (self._foto_principal_img.height() + 149) // 150
                    )
                    if fator > 1:
                        self._foto_principal_img = self._foto_principal_img.subsample(fator, fator)
                tk.Label(
                    self.root, image=self._foto_principal_img,
                    bg="#050505", bd=1, relief="solid"
                ).pack(pady=5)
            except Exception:
                self.criar_label(
                    self.root, "FOTO PRINCIPAL CADASTRADA (instale Pillow para exibir JPG)",
                    fg="#668888", font=("Consolas", 8)
                ).pack(pady=4)
        else:
            self.criar_label(
                self.root, "SEM FOTO PRINCIPAL",
                fg="#447777", font=("Consolas", 9)
            ).pack(pady=4)

        self.criar_label(self.root, nome, font=("Consolas", 17, "bold")).pack(pady=4)
        self.criar_label(self.root, f"STATUS VITAL: {status}", fg=cor_status,
                         font=("Consolas", 11, "bold")).pack(pady=3)
        geracao_pessoa = pessoa.get("geracao", 1)
        percentual = self.formatar_percentual(
            self.percentual_ancestral(geracao_pessoa)
        )
        rotulo_percentual = (
            "PESSOA DE REFERÊNCIA — 100% (não é ancestral)"
            if int(geracao_pessoa) == 1
            else f"CONTRIBUIÇÃO ANCESTRAL TEÓRICA: {percentual}"
        )
        self.criar_label(
            self.root, rotulo_percentual, fg="#00ccff",
            font=("Consolas", 10, "bold")
        ).pack(pady=3)

        quadro = tk.Frame(self.root, bg="#0a1114", highlightbackground="#00665c",
                          highlightthickness=1, padx=18, pady=12)
        quadro.pack(fill="both", expand=True, padx=22, pady=10)
        campos = [
            ("APELIDO", "apelido"), ("NASCIMENTO", "nascimento"),
            ("IDADE", "idade"), ("FALECIMENTO", "morte"),
            ("TERRA / ORIGEM", "terra"), ("GERAÇÃO", "geracao"),
            ("BIOGRAFIA", "bio")
        ]
        for linha, (rotulo, chave) in enumerate(campos):
            self.criar_label(quadro, rotulo + ":", bg="#0a1114",
                             fg="#00bfa5", font=("Consolas", 9, "bold")).grid(
                row=linha, column=0, sticky="nw", padx=(0, 12), pady=5
            )
            valor = str(pessoa.get(chave, "N") or "N")
            self.criar_label(quadro, valor, bg="#0a1114", fg="#d9ffff",
                             font=("Consolas", 9), wraplength=390, justify="left").grid(
                row=linha, column=1, sticky="w", pady=5
            )

        documentos = pessoa.get("documentos", [])
        self.criar_label(
            quadro, f"DOCUMENTOS ANEXADOS: {len(documentos)}",
            bg="#0a1114", fg="#00ccff", font=("Consolas", 9, "bold")
        ).grid(row=len(campos), column=0, columnspan=2, sticky="w", pady=(10, 3))
        if documentos:
            nomes_docs = " | ".join(
                f"{d.get('tipo', 'Documento')}: {d.get('nome', 'arquivo')}"
                for d in documentos
            )
            self.criar_label(
                quadro, nomes_docs, bg="#0a1114", fg="#9adbd5",
                font=("Consolas", 8), wraplength=450, justify="left"
            ).grid(row=len(campos) + 1, column=0, columnspan=2, sticky="w")

        botoes = tk.Frame(self.root, bg="#050505")
        botoes.pack(pady=8)
        self.criar_botao(
            botoes, "＋ PAI", lambda: self.adicionar_ancestral(pessoa_id, "pai_id"),
            width=9
        ).pack(side="left", padx=3)
        self.criar_botao(
            botoes, "＋ MÃE", lambda: self.adicionar_ancestral(pessoa_id, "mae_id"),
            width=9
        ).pack(side="left", padx=3)
        self.criar_botao(
            botoes, "✎ EDITAR", lambda: self.tela_form_pessoa_arvore(pessoa_id),
            width=13
        ).pack(side="left", padx=3)
        self.criar_botao(
            botoes, "🗑 EXCLUIR", lambda: self.excluir_pessoa_arvore(pessoa_id),
            bg="#330b10", fg="#ff7788", width=13
        ).pack(side="left", padx=4)
        self.criar_botao(
            botoes, "📎 DOCUMENTOS", lambda: self.tela_documentos_pessoa(pessoa_id),
            bg="#002b33", fg="#00ccff", width=15
        ).pack(side="left", padx=4)
        self.criar_botao(
            botoes, "🖼 FOTOS", lambda: self.tela_fotos_pessoa(pessoa_id),
            bg="#092820", fg="#00ff99", width=11
        ).pack(side="left", padx=4)
        self.criar_botao(
            botoes, "← VOLTAR À ÁRVORE", self.tela_arvore,
            bg="#222222", fg="#ffffff", width=20
        ).pack(side="left", padx=4)

    def adicionar_ancestral(self, pessoa_id, tipo_vinculo):
        """Cria um pai ou uma mãe acima da pessoa selecionada e vincula automaticamente."""
        pessoas = self.pessoas_do_perfil()
        pessoa = next((p for p in pessoas if p["id"] == pessoa_id), None)
        if not pessoa:
            return
        if pessoa.get(tipo_vinculo, "N") != "N":
            messagebox.showinfo("VÍNCULO EXISTENTE", "Esse vínculo já possui uma pessoa cadastrada. Use EDITAR para alterar.")
            return

        geracao_filho = int(pessoa.get("geracao", 1))
        geracao_ancestral = geracao_filho + 1
        if geracao_ancestral > 10:
            messagebox.showwarning("LIMITE DE GERAÇÕES", "A geração 10 é o limite configurado para esta árvore.")
            return

        parentesco = "pai" if tipo_vinculo == "pai_id" else "mãe"
        nome = simpledialog.askstring(
            f"ADICIONAR {parentesco.upper()}",
            f"Nome de {parentesco} (ou N se desconhecido):",
            parent=self.root
        )
        if nome is None:
            return
        sobrenome = simpledialog.askstring(
            f"ADICIONAR {parentesco.upper()}",
            f"Sobrenome de {parentesco} (ou N se desconhecido):",
            parent=self.root
        )
        if sobrenome is None:
            return

        ancestral = {
            "id": secrets.token_hex(6),
            "nome": nome.strip() or "N",
            "sobrenome": sobrenome.strip() or "N",
            "apelido": "N",
            "nascimento": "N",
            "idade": "N",
            "morte": "N",
            "terra": "N",
            "geracao": geracao_ancestral,
            "status": "N",
            "pai_id": "N",
            "mae_id": "N",
            "bio": "N",
            "atualizado_em": datetime.now().strftime("%d/%m/%Y %H:%M")
        }
        pessoa[tipo_vinculo] = ancestral["id"]
        pessoas.append(ancestral)
        if self.salvar_arvores():
            self.detalhes_pessoa_arvore(pessoa_id)
        else:
            pessoas.remove(ancestral)
            pessoa[tipo_vinculo] = "N"



    def tela_fotos_pessoa(self, pessoa_id):
        """Galeria de até 10 fotos por pessoa e seleção da foto principal."""
        from tkinter import filedialog

        if not pessoa_id:
            messagebox.showinfo(
                "SALVE PRIMEIRO",
                "Salve a pessoa antes de adicionar fotos, para vinculá-las ao registro correto."
            )
            return

        pessoa = next((p for p in self.pessoas_do_perfil() if p["id"] == pessoa_id), None)
        if not pessoa:
            messagebox.showerror("REGISTRO NÃO ENCONTRADO", "Não encontrei esta pessoa na árvore.")
            return

        self.limpar_tela()
        nome_pessoa = f"{pessoa.get('nome', 'N')} {pessoa.get('sobrenome', 'N')}".strip()
        self.criar_label(
            self.root, "🦇 GALERIA FOTOGRÁFICA",
            font=("Consolas", 16, "bold")
        ).pack(pady=(14, 4))
        self.criar_label(
            self.root, f"PERFIL {self.perfil_arvore_atual} // {nome_pessoa}",
            fg="#447777", font=("Consolas", 9)
        ).pack(pady=(0, 8))

        topo = tk.Frame(self.root, bg="#050505")
        topo.pack(fill="x", padx=14, pady=5)
        self.criar_botao(
            topo, "← DOSSIÊ", lambda: self.detalhes_pessoa_arvore(pessoa_id),
            bg="#222222", fg="#ffffff", width=12
        ).pack(side="left")
        self.criar_botao(
            topo, "＋ ADICIONAR FOTO", lambda: adicionar_foto(),
            bg="#092820", fg="#00ff99", width=18
        ).pack(side="right")

        fotos = pessoa.setdefault("fotos", [])
        lista = tk.Listbox(
            self.root, bg="#0a1114", fg="#00ffcc",
            selectbackground="#005044", font=("Consolas", 10), height=12
        )
        lista.pack(fill="both", expand=True, padx=16, pady=10)

        def atualizar_lista():
            lista.delete(0, tk.END)
            for indice, foto in enumerate(fotos, 1):
                principal = " ★ FOTO PRINCIPAL" if foto.get("caminho") == pessoa.get("foto_principal") else ""
                lista.insert(tk.END, f"{indice:02d}. {foto.get('nome', 'foto')}{principal}")
            contador.config(text=f"FOTOS: {len(fotos)}/10")

        contador = self.criar_label(
            self.root, f"FOTOS: {len(fotos)}/10",
            fg="#00ccff", font=("Consolas", 10, "bold")
        )
        contador.pack(pady=2)

        def adicionar_foto():
            if len(fotos) >= 10:
                messagebox.showwarning("LIMITE DE FOTOS", "Cada pessoa pode ter no máximo 10 fotos.")
                return
            caminho = filedialog.askopenfilename(
                title="Escolher foto",
                filetypes=[
                    ("Imagens", "*.png *.jpg *.jpeg *.gif *.bmp"),
                    ("PNG", "*.png"), ("JPG/JPEG", "*.jpg *.jpeg"),
                    ("Todos os arquivos", "*.*")
                ]
            )
            if not caminho:
                return
            ext = os.path.splitext(caminho)[1].lower()
            if ext not in (".png", ".jpg", ".jpeg", ".gif", ".bmp"):
                messagebox.showwarning("FORMATO NÃO SUPORTADO", "Escolha PNG, JPG, JPEG, GIF ou BMP.")
                return
            pasta_pessoa = os.path.join(
                PASTA_FOTOS, f"perfil_{self.perfil_arvore_atual}", pessoa_id
            )
            try:
                os.makedirs(pasta_pessoa, exist_ok=True)
                nome_arquivo = os.path.basename(caminho)
                destino = os.path.join(pasta_pessoa, nome_arquivo)
                base, ext_local = os.path.splitext(nome_arquivo)
                contador_nome = 2
                while os.path.exists(destino):
                    destino = os.path.join(pasta_pessoa, f"{base}_{contador_nome}{ext_local}")
                    contador_nome += 1
                shutil.copy2(caminho, destino)
            except OSError as erro:
                messagebox.showerror("ERRO AO COPIAR FOTO", f"Não foi possível copiar a foto:\n{erro}")
                return

            fotos.append({
                "nome": os.path.basename(destino),
                "caminho": destino,
                "adicionada_em": datetime.now().strftime("%d/%m/%Y %H:%M")
            })
            if self.salvar_arvores():
                atualizar_lista()
            else:
                fotos.pop()
                try:
                    os.remove(destino)
                except OSError:
                    pass

        def definir_principal():
            selecao = lista.curselection()
            if not selecao:
                messagebox.showinfo("SELECIONE UMA FOTO", "Selecione uma foto na lista primeiro.")
                return
            foto = fotos[selecao[0]]
            pessoa["foto_principal"] = foto.get("caminho", "")
            if self.salvar_arvores():
                atualizar_lista()
                messagebox.showinfo("FOTO PRINCIPAL", "Foto principal atualizada no dossiê.")
            else:
                pessoa.pop("foto_principal", None)

        def abrir_foto(event=None):
            selecao = lista.curselection()
            if not selecao:
                return
            caminho = fotos[selecao[0]].get("caminho", "")
            if caminho and os.path.isfile(caminho):
                try:
                    os.startfile(caminho)
                except OSError as erro:
                    messagebox.showerror("ERRO AO ABRIR", f"Não foi possível abrir a foto:\n{erro}")
            else:
                messagebox.showwarning("FOTO NÃO ENCONTRADA", "O arquivo pode ter sido movido ou apagado.")

        def remover_foto():
            selecao = lista.curselection()
            if not selecao:
                messagebox.showinfo("SELECIONE UMA FOTO", "Selecione uma foto na lista primeiro.")
                return
            indice = selecao[0]
            foto = fotos[indice]
            if not messagebox.askyesno("CONFIRMAR", f"Remover a foto '{foto.get('nome', 'foto')}'?"):
                return
            era_principal = pessoa.get("foto_principal") == foto.get("caminho")
            fotos.pop(indice)
            if era_principal:
                pessoa.pop("foto_principal", None)
            if self.salvar_arvores():
                try:
                    caminho = foto.get("caminho", "")
                    if caminho and os.path.isfile(caminho):
                        os.remove(caminho)
                except OSError:
                    messagebox.showwarning("ARQUIVO MANTIDO", "O registro foi removido, mas não foi possível apagar o arquivo.")
                atualizar_lista()

        lista.bind("<Double-Button-1>", abrir_foto)
        botoes = tk.Frame(self.root, bg="#050505")
        botoes.pack(pady=(0, 10))
        self.criar_botao(
            botoes, "★ DEFINIR COMO PRINCIPAL", definir_principal,
            bg="#002b33", fg="#00ccff", width=25
        ).pack(side="left", padx=4)
        self.criar_botao(
            botoes, "↗ ABRIR FOTO", abrir_foto,
            bg="#111111", fg="#ffffff", width=14
        ).pack(side="left", padx=4)
        self.criar_botao(
            botoes, "🗑 REMOVER FOTO", remover_foto,
            bg="#330b10", fg="#ff7788", width=15
        ).pack(side="left", padx=4)
        atualizar_lista()

    def tela_documentos_pessoa(self, pessoa_id):
        if not pessoa_id:
            messagebox.showinfo(
                "SALVE PRIMEIRO",
                "Salve a pessoa antes de anexar documentos. Assim os arquivos ficam ligados ao registro correto."
            )
            return
        from tkinter import filedialog

        pessoa = next((p for p in self.pessoas_do_perfil() if p["id"] == pessoa_id), None)
        if not pessoa:
            messagebox.showerror("REGISTRO NÃO ENCONTRADO", "Não encontrei esta pessoa na árvore.")
            return

        self.limpar_tela()
        nome_pessoa = f"{pessoa.get('nome', 'N')} {pessoa.get('sobrenome', 'N')}".strip()
        self.criar_label(
            self.root, "🦇 ARQUIVO DE DOCUMENTOS",
            font=("Consolas", 16, "bold")
        ).pack(pady=(14, 4))
        self.criar_label(
            self.root, f"PERFIL {self.perfil_arvore_atual} // {nome_pessoa}",
            fg="#447777", font=("Consolas", 9)
        ).pack(pady=(0, 10))

        topo = tk.Frame(self.root, bg="#050505")
        topo.pack(fill="x", padx=14, pady=5)
        self.criar_botao(
            topo, "← DOSSIÊ", lambda: self.detalhes_pessoa_arvore(pessoa_id),
            bg="#222222", fg="#ffffff", width=12
        ).pack(side="left")
        self.criar_botao(
            topo, "＋ ANEXAR ARQUIVO", lambda: anexar(),
            width=20
        ).pack(side="right")

        self.criar_label(
            self.root,
            "Imagens PNG/JPG e PDFs de certidões, registros e fotos históricas.",
            fg="#668888", font=("Consolas", 9)
        ).pack(pady=4)

        lista = tk.Listbox(
            self.root, bg="#0a1114", fg="#00ffcc",
            selectbackground="#005044", font=("Consolas", 10), height=14
        )
        lista.pack(fill="both", expand=True, padx=16, pady=10)

        documentos = pessoa.setdefault("documentos", [])

        def atualizar_lista():
            lista.delete(0, tk.END)
            for doc in documentos:
                lista.insert(tk.END, f"{doc.get('tipo', 'Documento')} | {doc.get('nome', 'arquivo')}")

        def anexar():
            caminho = filedialog.askopenfilename(
                title="Selecionar documento ou imagem",
                filetypes=[
                    ("Documentos e imagens", "*.png *.jpg *.jpeg *.pdf"),
                    ("Imagem PNG", "*.png"),
                    ("Imagem JPG", "*.jpg *.jpeg"),
                    ("PDF", "*.pdf"),
                    ("Todos os arquivos", "*.*")
                ]
            )
            if not caminho:
                return

            ext = os.path.splitext(caminho)[1].lower()
            if ext not in (".png", ".jpg", ".jpeg", ".pdf"):
                messagebox.showwarning(
                    "FORMATO NÃO SUPORTADO",
                    "Por enquanto, anexe arquivos PNG, JPG/JPEG ou PDF."
                )
                return

            tipos = [
                "Certidão de nascimento", "Certidão de casamento",
                "Certidão de óbito", "Documento de identidade",
                "Foto histórica", "Registro paroquial", "Outro documento"
            ]
            janela = tk.Toplevel(self.root)
            janela.title("Classificar documento")
            janela.configure(bg="#050505")
            janela.geometry("430x180")
            self.criar_label(
                janela, "TIPO DE DOCUMENTO",
                font=("Consolas", 12, "bold")
            ).pack(pady=(15, 5))
            tipo_var = tk.StringVar(value=tipos[0])
            menu = tk.OptionMenu(janela, tipo_var, *tipos)
            menu.config(bg="#111111", fg="#00ffcc", highlightthickness=0,
                        font=("Consolas", 9), width=30)
            menu["menu"].config(bg="#111111", fg="#00ffcc")
            menu.pack(pady=5)

            def confirmar():
                pasta_pessoa = os.path.join(
                    PASTA_DOCUMENTOS,
                    f"perfil_{self.perfil_arvore_atual}",
                    pessoa_id
                )
                try:
                    os.makedirs(pasta_pessoa, exist_ok=True)
                    nome_arquivo = os.path.basename(caminho)
                    destino = os.path.join(pasta_pessoa, nome_arquivo)
                    base, ext_local = os.path.splitext(nome_arquivo)
                    contador = 2
                    while os.path.exists(destino):
                        destino = os.path.join(pasta_pessoa, f"{base}_{contador}{ext_local}")
                        contador += 1
                    shutil.copy2(caminho, destino)
                except OSError as erro:
                    messagebox.showerror("ERRO AO ANEXAR", f"Não foi possível copiar o arquivo:\n{erro}")
                    return

                documentos.append({
                    "tipo": tipo_var.get(),
                    "nome": os.path.basename(destino),
                    "caminho": destino,
                    "adicionado_em": datetime.now().strftime("%d/%m/%Y %H:%M")
                })
                if self.salvar_arvores():
                    janela.destroy()
                    atualizar_lista()
                    messagebox.showinfo("DOCUMENTO ANEXADO", "Documento copiado para a pasta do BAT-ANALYZER.")
                else:
                    documentos.pop()
                    try:
                        os.remove(destino)
                    except OSError:
                        pass

            self.criar_botao(janela, "SALVAR DOCUMENTO", confirmar, width=22).pack(pady=8)

        def abrir_documento(event=None):
            selecao = lista.curselection()
            if not selecao:
                return
            doc = documentos[selecao[0]]
            caminho = doc.get("caminho", "")
            if caminho and os.path.isfile(caminho):
                try:
                    os.startfile(caminho)
                except OSError as erro:
                    messagebox.showerror("ERRO AO ABRIR", f"Não foi possível abrir o arquivo:\n{erro}")
            else:
                messagebox.showwarning("ARQUIVO NÃO ENCONTRADO", "O arquivo pode ter sido movido ou apagado.")

        def excluir_documento():
            selecao = lista.curselection()
            if not selecao:
                messagebox.showinfo("SELECIONE", "Selecione um documento da lista.")
                return
            indice = selecao[0]
            doc = documentos[indice]
            if not messagebox.askyesno("CONFIRMAR", f"Remover o documento '{doc.get('nome', 'arquivo')}' do dossiê?"):
                return
            # Remove o registro do dossiê e, quando possível, também o arquivo copiado.
            documentos.pop(indice)
            if self.salvar_arvores():
                caminho = doc.get("caminho", "")
                try:
                    if caminho and os.path.isfile(caminho):
                        os.remove(caminho)
                except OSError:
                    messagebox.showwarning("ARQUIVO MANTIDO", "O registro foi removido, mas não foi possível apagar o arquivo físico.")
                atualizar_lista()

        lista.bind("<Double-Button-1>", abrir_documento)
        botoes = tk.Frame(self.root, bg="#050505")
        botoes.pack(pady=(0, 10))
        self.criar_botao(
            botoes, "↗ ABRIR SELECIONADO", abrir_documento,
            bg="#002b33", fg="#00ccff", width=22
        ).pack(side="left", padx=5)
        self.criar_botao(
            botoes, "🗑 REMOVER DOCUMENTO", excluir_documento,
            bg="#330b10", fg="#ff7788", width=22
        ).pack(side="left", padx=5)
        atualizar_lista()

    def excluir_pessoa_arvore(self, pessoa_id):
        pessoas = self.pessoas_do_perfil()
        pessoa = next((p for p in pessoas if p["id"] == pessoa_id), None)
        if not pessoa:
            return
        if not messagebox.askyesno(
            "CONFIRMAR EXCLUSÃO",
            f"Excluir '{pessoa.get('nome', 'N')}' deste perfil?\n"
            "Os registros de filhos continuarão existindo, mas perderão este vínculo."
        ):
            return
        nome = pessoa.get("nome", "N")
        pessoas.remove(pessoa)
        for filho in pessoas:
            for chave in ("pai_id", "mae_id"):
                if filho.get(chave) == pessoa_id:
                    filho[chave] = "N"
        if self.salvar_arvores():
            messagebox.showinfo("REGISTRO EXCLUÍDO", f"{nome} foi removido do perfil.")
        self.tela_arvore()


    # =================================================
    # PERSISTÊNCIA DE PESSOAS
    # =================================================
    def salvar_dados(self):
        temporario = ARQUIVO_PESSOAS + ".tmp"
        try:
            with open(temporario, "w", encoding="utf-8") as arquivo:
                json.dump(self.pessoas, arquivo, ensure_ascii=False, indent=2)
            os.replace(temporario, ARQUIVO_PESSOAS)
            return True
        except OSError as erro:
            messagebox.showerror(
                "ERRO AO SALVAR",
                f"Não foi possível salvar os dados genealógicos:\n{erro}"
            )
            try:
                if os.path.exists(temporario):
                    os.remove(temporario)
            except OSError:
                pass
            return False

    def carregar_dados(self):
        try:
            with open(ARQUIVO_PESSOAS, "r", encoding="utf-8") as arquivo:
                dados = json.load(arquivo)
                if not isinstance(dados, list):
                    raise ValueError("Formato de dados genealógicos inválido.")
                self.pessoas = dados
        except FileNotFoundError:
            self.pessoas = []
        except (json.JSONDecodeError, OSError, ValueError) as erro:
            messagebox.showerror(
                "ERRO AO CARREGAR DADOS",
                "Não foi possível ler o arquivo de pessoas.\n"
                f"Detalhes: {erro}"
            )
            self.pessoas = []

    def modulo_em_construcao(self, nome):
        messagebox.showinfo(
            "EM DESENVOLVIMENTO",
            f"O módulo '{nome}' ainda está em desenvolvimento."
        )


if __name__ == "__main__":
    root = tk.Tk()
    app = BatAnalyzer(root)
    root.mainloop()
