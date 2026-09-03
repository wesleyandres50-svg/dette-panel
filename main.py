from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

app = FastAPI()

# Plantilla HTML embebida completamente corregida, con selector de servidores y guardado funcional
HTML_TEMPLATE = """
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
                <div onclick="selectServer('Capa\\'s Pizzeria', '🍕')" class="flex items-center gap-3 p-3 bg-cardbg hover:bg-slate-800 rounded-xl cursor-pointer transition-all border border-slate-700/50">
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
                            <i class="fa-solid fa-
