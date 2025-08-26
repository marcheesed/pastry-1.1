// dashboard search and sort
document.addEventListener('DOMContentLoaded', () => {
    const pastesContainer = document.querySelector('.pastes-table tbody');
    const searchInput = document.getElementById('search');
    const dropdown = document.querySelector('.sort-dropdown');
    if (!pastesContainer || !searchInput || !dropdown) {
        console.error('Required elements not found');
        return;
    }

    const selected = dropdown.querySelector('.selected');
    const optionsContainer = dropdown.querySelector('.sort-options');
    const optionsList = optionsContainer.querySelectorAll('div');

    const urlParams = new URLSearchParams(window.location.search);
    let currentSortValue = urlParams.get('sort') || '';
    let currentPage = parseInt(urlParams.get('page')) || 1;
    let debounceTimeout = null;

    const sortText = {
        'a-z': 'A-Z',
        'created': 'Created (Latest to Oldest)',
        'edited': 'Edited (Latest to Oldest)',
        '': 'Sort by'
    };
    selected.textContent = sortText[currentSortValue] || 'Sort by';
    selected.dataset.value = currentSortValue;
    searchInput.value = urlParams.get('search') || '';

    selected.addEventListener('click', () => {
        optionsContainer.style.display = optionsContainer.style.display === 'block' ? 'none' : 'block';
    });

    optionsList.forEach(option => {
        option.addEventListener('click', () => {
            currentSortValue = option.dataset.value || '';
            selected.textContent = option.textContent;
            selected.dataset.value = currentSortValue;
            optionsContainer.style.display = 'none';
            currentPage = 1;
            fetchPastes();
        });
    });

    document.addEventListener('click', (event) => {
        if (!dropdown.contains(event.target)) {
            optionsContainer.style.display = 'none';
        }
    });

    searchInput.addEventListener('input', () => {
        clearTimeout(debounceTimeout);
        debounceTimeout = setTimeout(() => {
            currentPage = 1;
            fetchPastes();
        }, 300);
    });

    document.querySelectorAll('.pagination-controls a.button').forEach(button => {
        button.addEventListener('click', (event) => {
            event.preventDefault();
            const href = button.getAttribute('href');
            if (!href) return; // skip if button is disabled
            console.log('Pagination clicked, href:', href);
            const params = new URLSearchParams(href.split('?')[1] || '');
            currentPage = parseInt(params.get('page')) || 1;
            console.log('New currentPage:', currentPage);
            fetchPastes();
        });
    });

    function fetchPastes() {
        const searchTerm = searchInput.value.trim();
        const params = new URLSearchParams();
        if (searchTerm.length > 0) params.append('search', encodeURIComponent(searchTerm));
        if (currentSortValue) params.append('sort', currentSortValue);
        params.append('page', currentPage);

        console.log('Fetching with params:', params.toString());

        fetch(`/api/pastes?${params.toString()}`, {
            method: 'GET',
            headers: { 'Accept': 'application/json' },
            credentials: 'same-origin',
        })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            console.log('API response:', data);
            pastesContainer.innerHTML = '';
            if (data.pastes.length === 0) {
                pastesContainer.innerHTML = '<tr><td colspan="1">No pastes found.</td></tr>';
                return;
            }
            for (const paste of data.pastes) {
                const tr = document.createElement('tr');
                const td = document.createElement('td');
                const a = document.createElement('a');
                a.href = `/${paste.token}`;
                a.textContent = paste.token;
                td.appendChild(a);
                tr.appendChild(td);
                pastesContainer.appendChild(tr);
            }

            const paginationControls = document.querySelector('.pagination-controls');
            const backButton = paginationControls.querySelector('a.button:nth-child(1)');
            const nextButton = paginationControls.querySelector('a.button:nth-child(2)');

            backButton.classList.toggle('disabled', !data.has_prev);
            if (data.has_prev) {
                backButton.href = `?page=${data.page - 1}${searchTerm ? `&search=${encodeURIComponent(searchTerm)}` : ''}${currentSortValue ? `&sort=${currentSortValue}` : ''}`;
            } else {
                backButton.removeAttribute('href');
            }

            nextButton.classList.toggle('disabled', !data.has_next);
            if (data.has_next) {
                nextButton.href = `?page=${data.page + 1}${searchTerm ? `&search=${encodeURIComponent(searchTerm)}` : ''}${currentSortValue ? `&sort=${currentSortValue}` : ''}`;
            } else {
                nextButton.removeAttribute('href');
            }

            const newUrl = `${window.location.pathname}?${params.toString()}`;
            window.history.pushState({}, '', newUrl);
        })
        .catch(error => {
            console.error('Fetch error:', error);
            pastesContainer.innerHTML = '<tr><td colspan="1">Error loading pastes.</td></tr>';
        });
    }

    fetchPastes();
});