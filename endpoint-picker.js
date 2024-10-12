class EndpointPicker extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this.data = [];
    this.filteredData = [];
    this.selectedEndpoint = null;
  }

  connectedCallback() {
    this.fetchEndpoints(); // Fetch the data on load
  }

  async fetchEndpoints() {
    try {
      const response = await fetch('epic.json'); // Fetch the epic.json file
      const jsonData = await response.json();
      this.data = this.parseEndpointData(jsonData); // Parse and store the relevant data
      this.render(); // Render the UI after the data is loaded
    } catch (error) {
      console.error('Failed to fetch the endpoint data:', error);
    }
  }

  parseEndpointData(jsonData) {
    return jsonData.entry.map(entry => {
      const resource = entry.resource;
      const org = resource.contained.find(contained => contained.resourceType === 'Organization');
      return {
        name: org.name,
        endpoint: resource.address
      };
    });
  }

  render() {
    this.shadowRoot.innerHTML = `
      <style>
        .endpoint-picker {
          margin: 20px auto;
          font-family: Arial, sans-serif;
        }
        .endpoint-picker input {
          padding: 8px;
          box-sizing: border-box;
        }
        .endpoint-picker ul {
          list-style: none;
          padding: 0;
          margin: 5px 0 0;
          max-height: 150px;
          overflow-y: auto;
        }
        .endpoint-picker ul li {
          padding: 8px;
          cursor: pointer;
        }
        .endpoint-picker ul li:hover {
          background-color: #f0f0f0;
        }
      </style>
      <div class="endpoint-picker">
        <input type="text" placeholder="Search for an organization..." id="search-input">
        <ul id="results"></ul>
      </div>
    `;
    this.shadowRoot.querySelector('#search-input').addEventListener('input', (e) => this.onSearch(e));
  }

  onSearch(event) {
    const searchTerm = event.target.value.toLowerCase();
    this.filteredData = this.data.filter(item => item.name.toLowerCase().includes(searchTerm));

    const resultsList = this.shadowRoot.querySelector('#results');
    resultsList.innerHTML = '';

    if (this.filteredData.length > 0) {
      this.filteredData.forEach(item => {
        const li = document.createElement('li');
        li.textContent = item.name;
        li.addEventListener('click', () => this.selectEndpoint(item));
        resultsList.appendChild(li);
      });
    }
  }

  selectEndpoint(item) {
    this.selectedEndpoint = item.endpoint;
    const event = new CustomEvent('endpoint-selected', { detail: { endpoint: this.selectedEndpoint } });
    this.dispatchEvent(event);
    this.shadowRoot.querySelector('#search-input').value = item.name;
    this.shadowRoot.querySelector('#results').innerHTML = '';
  }

  getSelectedEndpoint() {
    return this.selectedEndpoint;
  }
}

customElements.define('endpoint-picker', EndpointPicker);
