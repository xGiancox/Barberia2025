// Service Worker para PWA
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
        navigator.serviceWorker.register('/sw.js')
            .then(function(registration) {
                console.log('ServiceWorker registrado con éxito: ', registration.scope);
            })
            .catch(function(error) {
                console.log('Error registrando ServiceWorker: ', error);
            });
    });
}

// Funcionalidades generales de la app
document.addEventListener('DOMContentLoaded', function() {
    // Auto-calcular totales en formularios
    const priceInputs = document.querySelectorAll('input[name="price"]');
    const quantityInputs = document.querySelectorAll('input[name="quantity"]');

    function calculateTotal() {
        const price = parseFloat(this.form.querySelector('input[name="price"]').value) || 0;
        const quantity = parseInt(this.form.querySelector('input[name="quantity"]').value) || 0;
        const total = price * quantity;

        // Actualizar preview si existe
        const totalPreview = this.form.querySelector('#total-preview');
        const dividedPreview = this.form.querySelector('#divided-preview');

        if (totalPreview) {
            totalPreview.textContent = 'S/.' + total.toFixed(2);
            if (dividedPreview) {
                const isJefe = document.querySelector('small.text-muted')?.textContent.includes('jefe');
                const divided = isJefe ? total : total / 2;
                dividedPreview.textContent = 'S/.' + divided.toFixed(2);
            }
        }
    }

    priceInputs.forEach(input => input.addEventListener('input', calculateTotal));
    quantityInputs.forEach(input => input.addEventListener('input', calculateTotal));

    // Auto-seleccionar fecha de hoy por defecto
    const dateInputs = document.querySelectorAll('input[type="date"]');
    dateInputs.forEach(input => {
        if (!input.value) {
            const today = new Date().toISOString().split('T')[0];
            input.value = today;
        }
    });

    // Confirmación antes de acciones importantes
    const deleteButtons = document.querySelectorAll('.btn-danger, .btn-outline-danger');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('¿Estás seguro de que quieres realizar esta acción?')) {
                e.preventDefault();
            }
        });
    });

    // Mejora de experiencia en móviles
    if (window.innerWidth <= 768) {
        document.querySelectorAll('table').forEach(table => {
            table.classList.add('table-sm');
        });
    }

    // Auto-ocultar alerts después de 5 segundos
    setTimeout(() => {
        document.querySelectorAll('.alert').forEach(alert => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
});

// Instalar PWA
let deferredPrompt;
window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;

    // Mostrar botón de instalación
    const installButton = document.createElement('button');
    installButton.textContent = '📱 Instalar App';
    installButton.className = 'btn btn-success position-fixed';
    installButton.style.bottom = '20px';
    installButton.style.right = '20px';
    installButton.style.zIndex = '1000';
    installButton.style.boxShadow = '0 4px 12px rgba(0,0,0,0.3)';

    installButton.addEventListener('click', async () => {
        if (deferredPrompt) {
            deferredPrompt.prompt();
            const { outcome } = await deferredPrompt.userChoice;
            if (outcome === 'accepted') {
                installButton.style.display = 'none';
            }
            deferredPrompt = null;
        }
    });

    document.body.appendChild(installButton);
});

// Función para formatear números como soles
function formatSoles(amount) {
    return 'S/.' + parseFloat(amount).toFixed(2);
}