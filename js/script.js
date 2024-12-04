document.getElementById('fetchData').addEventListener('click', () => {
    const latitude = 34.05; // Example latitude
    const longitude = -118.25; // Example longitude

    fetch(`/fetch_ocean_data?latitude=${latitude}&longitude=${longitude}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch data');
            }
            return response.json();
        })
        .then(data => {
            document.getElementById('output').innerText = JSON.stringify(data, null, 2);
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('output').innerText = `Error: ${error.message}`;
        });
});
