<!DOCTYPE html>
<html lang="es" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Odette Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        darkbg: '#0b0f19',
                        sidebar: '#0f172a',
                        cardbg: '#1e293b',
                        accent: '#ff7b54'
                    }
                }
            }
        }
    </script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-darkbg text-slate-100 font-sans antialiased h-screen flex overflow-hidden">

    <div id="toast" class="fixed bottom-6 right-6 z-50 transform translate-y-20 opacity-0 transition-all duration-300 bg-emerald-600 text-white px-5 py-3 rounded-xl shadow-xl flex items-center gap-3 text-sm font-medium">
        <i class="fa-solid fa-circle-check text-lg"></i>
        <span id="toast-msg">Cambios guardados correctamente</span>
    </div>

    <div id="server-modal" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center hidden">
        <div class="bg-sidebar border border-slate-800 w-full max-w-md p-6 rounded-2xl shadow-2xl space-y-4">
            <div class="flex items-center justify-between">
                <h3 class="font-bold text-lg text-white">Selecciona un Servidor</h3>
                <button onclick="toggleServerModal(false)" class="text-slate-400 hover:text-white">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            <p class="text-xs text-slate-400">Elige el servidor de Discord que deseas administrar con Odette:</p>
            
            <div class="space-y-2 pt-2 max-h-60 overflow-y-auto">
                <div onclick="selectServer('Capa\'s Pizzeria', '🍕')" class="flex items-center gap-3 p-3 bg-cardbg hover:bg-slate-800 rounded-xl cursor-pointer transition-all border border-slate-700/50">
                    <div class="w-10 h-10 rounded-xl bg-orange-500/20 text-orange-400 font-bold flex items-center justify-center text-lg">🍕</div>
                    <div>
                        <h4 class="font-semibold text-sm text-white">Capa's Pizzeria</h4>
                        <p class="text-[11px] text-emerald-400 font-medium">● Bot Activo</p>
                    </div>
                </div>
                <div onclick="selectServer('Gaming Community', '🎮')" class="flex items-center gap-3 p-3 bg-cardbg hover:bg-slate-800 rounded-xl cursor-pointer transition-all border border-slate-700/50">
                    <div class="w-10 h-10 rounded-xl bg-indigo-500/20 text-indigo-400 font-bold flex items-center justify-center text-lg">🎮</div>
                    <div>
                        <h4 class="font-semibold text-sm text-white">Gaming Community</h4>
                        <p class="text-[11px] text-emerald-400 font-medium">● Bot Activo</p>
                    </div>
                </div>
                <div onclick="selectServer('Anime & Chill', '🌸')" class="flex items-center gap-3 p-3 bg-cardbg hover:bg-slate-800 rounded-xl cursor-pointer transition-all border border-slate-700/50">
                    <div class="w-10 h-10 rounded-xl bg-pink-500/20 text-pink-400 font-bold flex items-center justify-center text-lg">🌸</div>
                    <div>
                        <h4 class="font-semibold text-sm text-white">Anime & Chill</h4>
                        <p class="text-[11px] text-emerald-400 font-medium">● Bot Activo</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <aside class="w-64 bg-sidebar border-r border-slate-800 flex flex-col justify-between z-20">
        <div>
            <div class="flex items-center gap-3 px-6 py-5 border-b border-slate-800/65">
                <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-orange-400 to-pink-500 flex items-center justify-center shadow-lg shadow-orange-500/20 text-white font-bold text-lg">
                    🦢
                </div>
                <div class="overflow-hidden">
                    <h1 class="font-bold text-sm truncate text-white">Odette</h1>
                    <p id="sidebar-server-name" class="text-xs text-orange-400 font-medium truncate">🍕 Capa's Pizzeria</p>
                </div>
            </div>

            <nav class="p-4 space-y-6 overflow-y-auto max-h-[calc(100vh-140px)] custom-scroll">
                <div>
                    <p class="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-3 mb-2">General</p>
                    <div class="space-y-1">
                        <button onclick="switchTab('ajustes')" id="btn-ajustes" class="nav-btn w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-slate-400 hover:text-white hover:bg-slate-800/50">
                            <i class="fa-solid fa-sliders w-5"></i> Ajustes
                        </button>
                        <button onclick="switchTab('perfil')" id="btn-perfil" class="nav-btn w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-slate-400 hover:text-white hover:bg-slate-800/50 relative">
                            <i class="fa-solid fa-palette w-5"></i> Perfil del bot
                            <span class="ml-auto text-[10px] bg-orange-500 text-white px-1.5 py-0.5 rounded-md font-bold">ACTIVO</span>
                        </button>
                    </div>
                </div>

                <div>
                    <p class="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-3 mb-2">Miembros</p>
                    <div class="space-y-1">
                        <button onclick="switchTab('bienvenidas')" id="btn-bienvenidas" class="nav-btn w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-slate-400 hover:text-white hover:bg-slate-800/50">
                            <i class="fa-solid fa-hand-wave w-5"></i> Bienvenidas
                        </button>
                        <button onclick="switchTab('boosts')" id="btn-boosts" class="nav-btn w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-slate-400 hover:text-white hover:bg-slate-800/50 relative">
                            <i class="fa-solid fa-gem w-5"></i> Boosts
                            <span class="ml-auto text-[10px] bg-orange-500 text-white px-1.5 py-0.5 rounded-md font-bold">NUEVO</span>
                        </button>
                        <button onclick="switchTab('autoroles')" id="btn-autoroles" class="nav-btn w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-slate-400 hover:text-white hover:bg-slate-800/50">
                            <i class="fa-solid fa-user-shield w-5"></i> Auto Roles
                        </button>
                    </div>
                </div>

                <div>
                    <p class="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-3 mb-2">Comunidad</p>
                    <div class="space-y-1">
                        <button onclick="switchTab('niveles')" id="btn-niveles" class="nav-btn w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-slate-400 hover:text-white hover:bg-slate-800/50 relative">
                            <i class="fa-solid fa-chart-column w-5"></i> Niveles (XP)
                            <span class="ml-auto text-[10px] bg-orange-500 text-white px-1.5 py-0.5 rounded-md font-bold">NUEVO</span>
                        </button>
                        <button onclick="switchTab('starboard')" id="btn-starboard" class="nav-btn w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-slate-400 hover:text-white hover:bg-slate-800/50">
                            <i class="fa-solid fa-star w-5"></i> Starboard
                        </button>
                        <button onclick="switchTab('economia')" id="btn-economia" class="nav-btn w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-slate-400 hover:text-white hover:bg-slate-800/50">
                            <i class="fa-solid fa-coins w-5"></i> Economía
                        </button>
                        <button onclick="switchTab('tickets')" id="btn-tickets" class="nav-btn w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-slate-400 hover:text-white hover:bg-slate-800/50">
                            <i class="fa-solid fa-ticket w-5"></i> Tickets
                        </button>
                    </div>
                </div>

                <div>
                    <p class="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-3 mb-2">Seguridad</p>
                    <div class="space-y-1">
                        <button onclick="switchTab('antiraid')" id="btn-antiraid" class="nav-btn w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-slate-400 hover:text-white hover:bg-slate-800/50">
                            <i class="fa-solid fa-shield-halved w-5"></i> Anti-raid
                        </button>
                    </div>
                </div>
            </nav>
        </div>

        <div class="p-4 border-t border-slate-800/60">
            <button onclick="toggleServerModal(true)" class="flex items-center justify-center gap-2 w-full bg-slate-800/50 hover:bg-slate-800 text-slate-300 py-2.5 rounded-xl text-xs font-semibold transition-all">
                <i class="fa-solid fa-arrow-left"></i> Cambiar Servidor
            </button>
        </div>
    </aside>

    <main class="flex-1 flex flex-col bg-darkbg overflow-y-auto">
        
        <header class="h-16 border-b border-slate-800/60 px-8 flex items-center justify-between bg-darkbg/50 backdrop-blur sticky top-0 z-10">
            <div class="flex items-center gap-2 text-sm text-slate-400">
                <span id="topbar-server-name" class="text-white font-semibold">Capa's Pizzeria</span>
                <i class="fa-solid fa-chevron-right text-xs text-slate-600"></i>
                <span id="current-page-title" class="text-orange-400 font-medium">Ajustes</span>
            </div>
            <div class="flex items-center gap-4">
                <button onclick="saveSettings()" class="bg-gradient-to-r from-orange-500 to-amber-500 hover:opacity-90 text-white px-4 py-2 rounded-xl text-xs font-bold transition-all shadow-lg shadow-orange-500/20 flex items-center gap-2">
                    <i class="fa-solid fa-floppy-disk"></i> Guardar Cambios
                </button>
                <div class="w-8 h-8 rounded-full bg-orange-500/20 text-orange-400 font-bold flex items-center justify-center border border-orange-500/30 text-xs">
                    MP
                </div>
            </div>
        </header>

        <div class="p-8 max-w-5xl w-full mx-auto pb-20">
            
            <div id="tab-ajustes" class="tab-content space-y-6">
                <div>
                    <h2 class="text-xl font-bold text-white">Configuración General</h2>
                    <p class="text-sm text-slate-400">Administra los parámetros generales de tu servidor.</p>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="bg-cardbg border border-slate-800 p-5 rounded-2xl">
                        <h3 class="font-semibold text-sm text-white mb-1">Prefijo del bot</h3>
                        <p class="text-xs text-slate-400 mb-3">Define el prefijo para los comandos de texto.</p>
                        <input id="input-prefix" type="text" value="!" class="bg-darkbg border border-slate-700 rounded-xl px-3 py-2 text-sm w-full text-white focus:outline-none focus:border-orange-500">
                    </div>
                    <div class="bg-cardbg border border-slate-800 p-5 rounded-2xl">
                        <h3 class="font-semibold text-sm text-white mb-1">Idioma</h3>
                        <p class="text-xs text-slate-400 mb-3">Selecciona el idioma del bot.</p>
                        <select id="select-lang" class="bg-darkbg border border-slate-700 rounded-xl px-3 py-2 text-sm w-full text-white focus:outline-none focus:border-orange-500">
                            <option value="es">Español (ES)</option>
                            <option value="en">English (EN)</option>
                        </select>
                    </div>
                </div>
            </div>

            <div id="tab-perfil" class="tab-content space-y-6 hidden">
                <div>
                    <h2 class="text-xl font-bold text-white">Personalización del Bot</h2>
                    <p class="text-sm text-slate-400">Configura los colores y la apariencia visual de los embeds.</p>
                </div>
                <div class="bg-cardbg border border-slate-800 p-6 rounded-2xl space-y-4">
                    <h3 class="font-semibold text-sm text-white">Color de embeds</h3>
                    <div class="flex flex-wrap gap-3 pt-2">
                        <button onclick="setColor('#AFD7E6', this)" class="color-btn w-9 h-9 rounded-full bg-[#AFD7E6] border-2 border-transparent hover:scale-110 transition-all shadow-md"></button>
                        <button onclick="setColor('#38bdf8', this)" class="color-btn w-9 h-9 rounded-full bg-sky-400 border-2 border-transparent hover:scale-110 transition-all shadow-md"></button>
                        <button onclick="setColor('#3b82f6', this)" class="color-btn w-9 h-9 rounded-full bg-blue-500 border-2 border-transparent hover:scale-110 transition-all shadow-md"></button>
                        <button onclick="setColor('#6366f1', this)" class="color-btn w-9 h-9 rounded-full bg-indigo-500 border-2 border-transparent hover:scale-110 transition-all shadow-md"></button>
                        <button onclick="setColor('#a855f7', this)" class="color-btn w-9 h-9 rounded-full bg-purple-500 border-2 border-transparent hover:scale-110 transition-all shadow-md"></button>
                        <button onclick="setColor('#ec4899', this)" class="color-btn w-9 h-9 rounded-full bg-pink-500 border-2 border-transparent hover:scale-110 transition-all shadow-md"></button>
                        <button onclick="setColor('#f43f5e', this)" class="color-btn w-9 h-9 rounded-full bg-rose-500 border-2 border-transparent hover:scale-110 transition-all shadow-md"></button>
                        <button onclick="setColor('#dc2626', this)" class="color-btn w-9 h-9 rounded-full bg-red-600 border-2 border-transparent hover:scale-110 transition-all shadow-md"></button>
                        <button onclick="setColor('#f59e0b', this)" class="color-btn w-9 h-9 rounded-full bg-amber-500 border-2 border-transparent hover:scale-110 transition-all shadow-md"></button>
                        <button onclick="setColor('#10b981', this)" class="color-btn w-9 h-9 rounded-full bg-emerald-500 border-2 border-transparent hover:scale-110 transition-all shadow-md"></button>
                    </div>

                    <div class="mt-6 p-4 bg-darkbg border border-slate-800 rounded-xl">
                        <p class="text-xs text-slate-400 mb-2 font-medium">Vista previa en tiempo real</p>
                        <div id="preview-box" class="border-l-4 border-[#AFD7E6] bg-slate-900/80 p-4 rounded-r-xl text-xs text-slate-300 shadow-inner transition-colors duration-300">
                            <strong class="text-white block mb-1">¡Embed de prueba!</strong>
                            Así se verá el borde de color configurado en este servidor.
                        </div>
                    </div>
                </div>
            </div>

            <div id="tab-bienvenidas" class="tab-content space-y-6 hidden">
                <div class="bg-cardbg border border-slate-800 p-6 rounded-2xl space-y-4">
                    <h3 class="font-semibold text-sm text-white">Mensajes de Bienvenida</h3>
                    <input type="checkbox" id="check-welcome" class="w-5 h-5 accent-orange-500 rounded cursor-pointer">
                    <input id="input-welcome-channel" type="text" placeholder="#general" class="bg-darkbg border border-slate-700 rounded-xl px-3 py-2 text-sm w-full text-white">
                    <textarea id="input-welcome-msg" rows="3" class="bg-darkbg border border-slate-700 rounded-xl px-3 py-2 text-sm w-full text-white"></textarea>
                </div>
            </div>

            <div id="tab-boosts" class="tab-content space-y-6 hidden">
                <div class="bg-cardbg border border-slate-800 p-6 rounded-2xl">
                    <input type="checkbox" id="check-boosts" class="w-5 h-5 accent-orange-500 rounded cursor-pointer">
                </div>
            </div>

            <div id="tab-autoroles" class="tab-content space-y-6 hidden"><div class="bg-cardbg border border-slate-800 p-6 rounded-2xl"><p class="text-sm">Auto Roles</p></div></div>
            <div id="tab-niveles" class="tab-content space-y-6 hidden"><div class="bg-cardbg border border-slate-800 p-6 rounded-2xl"><p class="text-sm">Niveles</p></div></div>
            <div id="tab-starboard" class="tab-content space-y-6 hidden"><div class="bg-cardbg border border-slate-800 p-6 rounded-2xl"><p class="text-sm">Starboard</p></div></div>
            <div id="tab-economia" class="tab-content space-y-6 hidden"><div class="bg-cardbg border border-slate-800 p-6 rounded-2xl"><p class="text-sm">Economía</p></div></div>
            <div id="tab-tickets" class="tab-content space-y-6 hidden"><div class="bg-cardbg border border-slate-800 p-6 rounded-2xl"><p class="text-sm">Tickets</p></div></div>
            
            <div id="tab-antiraid" class="tab-content space-y-6 hidden">
                <div class="bg-cardbg border border-slate-800 p-6 rounded-2xl">
                    <input type="checkbox" id="check-antiraid" class="w-5 h-5 accent-orange-500 rounded cursor-pointer" checked>
                </div>
            </div>

        </div>
    </main>

    <script>
        let currentServer = "Capa's Pizzeria";
        let serverEmoji = "🍕";
        let currentColor = '#AFD7E6';

        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            const targetTab = document.getElementById('tab-' + tabId);
            if(targetTab) targetTab.classList.remove('hidden');

            document.querySelectorAll('.nav-btn').forEach(btn => {
                btn.classList.remove('bg-slate-800', 'text-white', 'shadow-sm');
                btn.classList.add('text-slate-400');
            });

            const activeBtn = document.getElementById('btn-' + tabId);
            if (activeBtn) {
                activeBtn.classList.remove('text-slate-400');
                activeBtn.classList.add('bg-slate-800', 'text-white', 'shadow-sm');
            }
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        function toggleServerModal(show) {
            const modal = document.getElementById('server-modal');
            if(show) modal.classList.remove('hidden');
            else modal.classList.add('hidden');
        }

        function selectServer(name, emoji) {
            currentServer = name;
            serverEmoji = emoji;
            document.getElementById('sidebar-server-name').innerText = emoji + ' ' + name;
            document.getElementById('topbar-server-name').innerText = name;
            toggleServerModal(false);
        }

        function setColor(hex, element) {
            currentColor = hex;
            document.getElementById('preview-box').style.borderLeftColor = hex;
            document.querySelectorAll('.color-btn').forEach(btn => btn.classList.remove('ring-2', 'ring-white', 'scale-110'));
            if(element) element.classList.add('ring-2', 'ring-white', 'scale-110');
        }

        function saveSettings() {
            const toast = document.getElementById('toast');
            toast.classList.remove('translate-y-20', 'opacity-0');
            setTimeout(() => toast.classList.add('translate-y-20', 'opacity-0'), 3000);
        }

        window.addEventListener('DOMContentLoaded', () => {
            switchTab('ajustes');
        });
    </script>
</body>
</html>
