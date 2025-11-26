// Modal management
function showModal(id) {
    const modal = document.getElementById(id);
    if (modal) {
        modal.classList.add('active');
    }
}

function hideModal(id) {
    const modal = document.getElementById(id);
    if (modal) {
        modal.classList.remove('active');
    }
}

function hideAllModals() {
    document.querySelectorAll('.modal-backdrop').forEach(function(modal) {
        modal.classList.remove('active');
    });
}

// Close modal on backdrop click (only for view modals, not edit/create forms)
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal-backdrop')) {
        // don't close if modal contains a form (edit/create mode)
        var modalContent = e.target.querySelector('#modal-content');
        if (modalContent && modalContent.querySelector('form')) {
            return; // don't close forms on backdrop click
        }
        hideAllModals();
    }
});

// Close modal on Escape key (only for view modals, not edit/create forms)
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        var mainModal = document.getElementById('main-modal');
        if (mainModal && mainModal.classList.contains('active')) {
            var modalContent = mainModal.querySelector('#modal-content');
            if (modalContent && modalContent.querySelector('form')) {
                return; // don't close forms on Escape
            }
        }
        hideAllModals();
    }
});

// Custom confirm dialog for delete
let confirmCallback = null;

function showConfirmDelete(key, deleteUrl) {
    const modal = document.getElementById('confirm-modal');
    const keySpan = document.getElementById('confirm-key');
    const confirmBtn = document.getElementById('confirm-delete-btn');

    if (modal && keySpan && confirmBtn) {
        keySpan.textContent = key;
        confirmBtn.setAttribute('hx-delete', deleteUrl);
        htmx.process(confirmBtn);
        showModal('confirm-modal');
    }
}

// HTMX event handlers
document.body.addEventListener('htmx:afterRequest', function(evt) {
    // Close modal after successful create/edit/delete
    if (evt.detail.successful) {
        const trigger = evt.detail.elt;
        if (trigger.hasAttribute('data-close-modal')) {
            hideAllModals();
        }
    }
});

// Show modal after loading content
document.body.addEventListener('htmx:afterSwap', function(evt) {
    const target = evt.detail.target;
    if (target.id === 'modal-content') {
        showModal('main-modal');
    }
});
