from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

app = FastAPI()

# Plantilla HTML embebida con diseño moderno estilo Okaa / Discord Bots Dashboard
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Odette Dashboard</title>
    <!-- Tailwind CSS CDN -->
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
    <!-- FontAwesome para Iconos -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-darkbg text-slate-100 font-sans antialiased h-screen flex overflow-hidden">

    <!-- SIDEBAR MODERNO (FIJO SIN SCROLL INTERNO CAÓTICO) -->
    <aside class="w-64 bg-sidebar border-r border-slate-800 flex flex-col justify-between z-20">
        <div>
            <!-- Header del Bot -->
            <div class="flex items-center gap-3 px-6 py-5 border-b border-slate-800/60">
                <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-orange-400 to-pink-500 flex items-center justify-center shadow-lg shadow-orange-500/20 text-white font-bold text-lg">
                    🦢
                </div>
                <div class="overflow-hidden">
                    <h1 class="font-bold text-sm truncate text-white">Odette</h1>
                    <p class="text-xs text-orange-400 font-medium truncate">🍕 Capa's Pizzeria</p>
                </div>
            </div>

            <!-- Menú de Navegación por Secciones -->
            <nav class="p-4 space-y-6 overflow-y-auto max-h-[calc(100vh-140px)] custom-scroll">
                <!-- GENERAL -->
                <div>
                    <p class="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-3 mb-2">General</p>
                    <div class="space-y-1">
                        <button onclick="switchTab('ajustes')" id="btn-ajustes" class="nav-btn w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-slate-400 hover:text-white hover:bg-slate-800/50">
                            <i class="fa-solid fa-sliders w-5"></i> Ajustes
                        </button>
                        <button onclick="switchTab('perfil')" id="btn-perfil" class="nav-btn w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-slate-400 hover:text-white hover:bg-slate-800/50 relative">
                            <i class="fa-solid fa-palette w-5"></i> Perfil del bot
                            <span class="ml-auto text-[10px] bg-orange-500 text-white px-1.5 py-0.5 rounded-md font-bold">NUEVO</span>
                        </button>
                    </div>
                </div>

                <!-- MIEMBROS -->
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

                <!-- COMUNIDAD -->
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

                <!-- SEGURIDAD -->
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

        <!-- Footer Sidebar -->
        <div class="p-4 border-t border-slate-800/60">
            <a href="#" class="flex items-center justify-center gap-2 w-full bg-slate-800/50 hover:bg-slate-800 text-slate-300 py-2.5 rounded-xl text-xs font-semibold transition-all">
                <i class="fa-solid fa-arrow-left"></i> Cambiar Servidor
            </a>
        </div>
    </aside>

    <!-- CONTENIDO PRINCIPAL -->
    <main class="flex-1 flex flex-col bg-darkbg overflow-y-auto">
        
        <!-- TOPBAR LIMPIA Y MINIMALISTA -->
        <header class="h-16 border-b border-slate-800/60 px-8 flex items-center justify-between bg-darkbg/50 backdrop-blur sticky top-0 z-10">
            <div class="flex items-center gap-2 text-sm text-slate-400">
                <span class="text-white font-semibold">Capa's Pizzeria</span>
                <i class="fa-solid fa-chevron-right text-xs text-slate-600"></i>
                <span id="current-page-title" class="text-orange-400 font-medium">Ajustes</span>
            </div>
            <div class="flex items-center gap-4">
                <button class="bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-2">
                    <i class="fa-solid fa-rotate"></i> Recargar
                </button>
                <div class="w-8 h-8 rounded-full bg-orange-500/20 text-orange-400 font-bold flex items-center justify-center border border-orange-500/30 text-xs">
                    MP
                </div>
            </div>
        </header>

        <!-- CONTENEDOR DE SECCIONES (VISTAS INDEPENDIENTES) -->
        <div class="p-8 max-w-6xl w-full mx-auto">
            
            <!-- SECCIÓN: AJUSTES -->
            <div id="tab-ajustes" class="tab-content space-y-6">
                <div>
                    <h2 class="text-xl font-bold text-white">Configuración General</h2>
                    <p class="text-sm text-slate-400">Administra los parámetros generales de tu servidor.</p>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="bg-cardbg border border-slate-800 p-5 rounded-2xl">
                        <h3 class="font-semibold text-sm text-white mb-1">Prefijo del bot</h3>
                        <p class="text-xs text-slate-400 mb-3">Define el prefijo para los comandos de texto tradicional.</p>
                        <input type="text" value="!" class="bg-darkbg border border-slate-700 rounded-xl px-3 py-2 text-sm w-full text-white focus:outline-none focus:border-orange-500">
                    </div>
                    <div class="bg-cardbg border border-slate-800 p-5 rounded-2xl">
                        <h3 class="font-semibold text-sm text-white mb-1">Idioma</h3>
                        <p class="text-xs text-slate-400 mb-3">Selecciona el idioma predeterminado de las respuestas.</p>
                        <select class="bg-darkbg border border-slate-700 rounded-xl px-3 py-2 text-sm w-full text-white focus:outline-none focus:border-orange-500">
                            <option>Español (ES)</option>
                            <option>English (EN)</option>
                        </select>
                    </div>
                </div>
            </div>

            <!-- SECCIÓN: PERFIL DEL BOT -->
            <div id="tab-perfil" class="tab-content space-y-6 hidden">
                <div>
                    <h2 class="text-xl font-bold text-white">Personalización del Bot</h2>
                    <p class="text-sm text-slate-400">Configura los colores y la apariencia visual de los embeds de respuesta.</p>
                </div>
                <div class="bg-cardbg border border-slate-800 p-6 rounded-2xl space-y-4">
                    <h3 class="font-semibold text-sm text-white">Color de embeds</h3>
                    <p class="text-xs text-slate-400">Color principal de los embeds de respuesta en este servidor (comandos, bienvenidas, utilidades...).</p>
                    
                    <div class="flex flex-wrap gap-2 pt-2">
                        <button class="w-8 h-8 rounded-full bg-[#AFD7E6] border-2 border-white shadow-md"></button>
                        <button class="w-8 h-8 rounded-full bg-sky-400 hover:scale-105 transition-transform"></button>
                        <button class="w-8 h-8 rounded-full bg-blue-500 hover:scale-105 transition-transform"></button>
                        <button class="w-8 h-8 rounded-full bg-indigo-500 hover:scale-105 transition-transform"></button>
                        <button class="w-8 h-8 rounded-full bg-purple-500 hover:scale-105 transition-transform"></button>
                        <button class="w-8 h-8 rounded-full bg-pink-500 hover:scale-105 transition-transform"></button>
                        <button class="w-8 h-8 rounded-full bg-rose-500 hover:scale-105 transition-transform"></button>
                        <button class="w-8 h-8 rounded-full bg-red-600 hover:scale-105 transition-transform"></button>
                        <button class="w-8 h-8 rounded-full bg-amber-500 hover:scale-105 transition-transform"></button>
                        <button class="w-8 h-8 rounded-full bg-emerald-500 hover:scale-105 transition-transform"></button>
                        <button class="w-8 h-8 rounded-full bg-teal-400 hover:scale-105 transition-transform"></button>
                        <button class="w-8 h-8 rounded-full bg-slate-400 hover:scale-105 transition-transform"></button>
                    </div>

                    <div class="mt-6 p-4 bg-darkbg border border-slate-800 rounded-xl">
                        <p class="text-xs text-slate-400 mb-2 font-medium">Vista previa</p>
                        <div class="border-l-4 border-[#AFD7E6] bg-slate-900/60 p-3 rounded-r-lg text-xs text-slate-300">
                            Así se verá el borde de color en los embeds de este server.
                        </div>
                    </div>
                </div>
            </div>

            <!-- SECCIÓN: BIENVENIDAS -->
            <div id="tab-bienvenidas" class="tab-content space-y-6 hidden">
                <div>
                    <h2 class="text-xl font-bold text-white">Mensajes de Bienvenida</h2>
                    <p class="text-sm text-slate-400">Saluda automáticamente a los nuevos usuarios que se unan.</p>
                </div>
                <div class="bg-cardbg border border-slate-800 p-6 rounded-2xl">
                    <p class="text-sm text-slate-300">Configuración de canales de bienvenida y tarjetas personalizadas próximamente activa.</p>
                </div>
            </div>

            <!-- SECCIÓN: BOOSTS -->
            <div id="tab-boosts" class="tab-content space-y-6 hidden">
                <div>
                    <h2 class="text-xl font-bold text-white">Sistema de Boosts</h2>
                    <p class="text-sm text-slate-400">Agradece las mejoras de servidor de tus usuarios con roles automáticos.</p>
                </div>
            </div>

            <!-- SECCIÓN: AUTO ROLES -->
            <div id="tab-autoroles" class="tab-content space-y-6 hidden">
                <div>
                    <h2 class="text-xl font-bold text-white">Auto Roles</h2>
                    <p class="text-sm text-slate-400">Asigna roles automáticos a los miembros al unirse.</p>
                </div>
            </div>

            <!-- SECCIÓN: NIVELES -->
            <div id="tab-niveles" class="tab-content space-y-6 hidden">
                <div>
                    <h2 class="text-xl font-bold text-white">Sistema de Niveles (XP)</h2>
                    <p class="text-sm text-slate-400">Premia la actividad de tus usuarios chateando.</p>
                </div>
            </div>

            <!-- SECCIÓN: STARBOARD -->
            <div id="tab-starboard" class="tab-content space-y-6 hidden">
                <div>
                    <h2 class="text-xl font-bold text-white">Starboard</h2>
                    <p class="text-sm text-slate-400">Destaca los mensajes más divertidos con reacciones de estrellas.</p>
                </div>
            </div>

            <!-- SECCIÓN: ECONOMÍA -->
            <div id="tab-economia" class="tab-content space-y-6 hidden">
                <div>
                    <h2 class="text-xl font-bold text-white">Economía del Servidor</h2>
                    <p class="text-sm text-slate-400">Monedas, tiendas, trabajos y apuestas.</p>
                </div>
            </div>

            <!-- SECCIÓN: TICKETS -->
            <div id="tab-tickets" class="tab-content space-y-6 hidden">
                <div>
                    <h2 class="text-xl font-bold text-white">Sistema de Tickets</h2>
                    <p class="text-sm text-slate-400">Soporte privado para los miembros de tu comunidad.</p>
                </div>
            </div>

            <!-- SECCIÓN: ANTI-RAID -->
            <div id="tab-antiraid" class="tab-content space-y-6 hidden">
                <div>
                    <h2 class="text-xl font-bold text-white">Seguridad Anti-Raid</h2>
                    <p class="text-sm text-slate-400">Protege tu servidor contra ataques masivos y bots maliciosos.</p>
                </div>
            </div>

        </div>
    </main>

    <!-- SCRIPT DE NAVEGACIÓN LIMPIA -->
    <script>
        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => {
                el.classList.add('hidden');
            });
            document.getElementById('tab-' + tabId).classList.remove('hidden');

            document.querySelectorAll('.nav-btn').forEach(btn => {
                btn.classList.remove('bg-slate-800', 'text-white', 'shadow-sm');
                btn.classList.add('text-slate-400');
            });

            const activeBtn = document.getElementById('btn-' + tabId);
            if (activeBtn) {
                activeBtn.classList.remove('text-slate-400');
                activeBtn.classList.add('bg-slate-800', 'text-white', 'shadow-sm');
            }

            const titles = {
                'ajustes': 'Ajustes',
                'perfil': 'Perfil del bot',
                'bienvenidas': 'Bienvenidas',
                'boosts': 'Boosts',
                'autoroles': 'Auto Roles',
                'niveles': 'Niveles (XP)',
                'starboard': 'Starboard',
                'economia': 'Economía',
                'tickets': 'Tickets',
                'antiraid': 'Anti-raid'
            };
            document.getElementById('current-page-title').innerText = titles[tabId] || 'Panel';
        }

        switchTab('ajustes');
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return HTML_TEMPLATE
