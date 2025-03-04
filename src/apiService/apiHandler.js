const axios = require('axios');
const report = 'all_projects_violations';

const apiCaller = {
    async apvReport() {
        try {
            console.log(process.env.BASE_URL);

            let config = {
                method: 'post',
                maxBodyLength: Infinity,
                url: `${process.env.BASE_URL}/${process.env.ORGANIZATION}/reports/${report}/generate?catalog_name=${process.env.CATALOG}`,
                headers: { 
                    'Authorization': `Bearer ${process.env.TIDELIFT_ORG_TOKEN}`
                },
            };

            const response = await axios.request(config);
        
            const reportId = response.data.report_id
            let status = await this.getReportStatus(reportId);

            while (status.status !== 'completed') {
                await new Promise(resolve => setTimeout(resolve, 5000)); // Wait for 5 seconds before checking the status again
                status = await this.getReportStatus(reportId);
                console.log(`status: ${status.status}`);
            }
            const data = await this.fetchJson(reportId)
            return data.report;
        } catch (error) {
            this.logAxiosError(error);
        }
    },

    async getReportStatus(reportId) {
        try {
            const config = {
                method: 'get',
                url: `${process.env.BASE_URL}/${process.env.ORGANIZATION}/reports/${report}/status?report_id=${reportId}`,
                headers: { 
                    'Authorization': `Bearer ${process.env.TIDELIFT_ORG_TOKEN}` 
                }
            };

            const response = await axios.request(config);
            return response.data;
        } catch (error) {
            this.logAxiosError(error);
            throw error;
        }
    },

    async fetchJson(reportId) {
        try {
            const config = {
                method: 'get',
                maxBodyLength: Infinity,
                url: `${process.env.BASE_URL}/${process.env.ORGANIZATION}/reports/${report}?report_id=${reportId}`,
                headers: { 
                    'Content-Type': 'application/json', 
                    'Authorization': `Bearer ${process.env.TIDELIFT_ORG_TOKEN}`
                }
            };

            const response = await axios.request(config);
            return response.data;
        } catch (error) {
            this.logAxiosError(error);
            throw error;
        }
    },

    async bulkPackageLookup(packages){
        const config = {
            method: 'POST',
            maxBodyLength: Infinity,
            url: `${process.env.BASE_URL}/packages/lookup`,
            headers: { 
                'Content-Type': 'application/json', 
                'Authorization': `Bearer ${process.env.TIDELIFT_ORG_TOKEN}`
            },
            data : {
                packages: packages
            }
        };
        try{
            const response = await axios.request(config);
            //console.log("PACKAGES: "+JSON.stringify(response.data))
            return response.data.packages;
        } catch (error) {
            this.logAxiosError(error);
            throw error;
        }
    },
    async bulkReleaseLookup(releaseData){
        const config = {
            method: 'POST',
            maxBodyLength: Infinity,
            url: `${process.env.BASE_URL}/releases/lookup`,
            headers: { 
                'Content-Type': 'application/json', 
                'Authorization': `Bearer ${process.env.TIDELIFT_ORG_TOKEN}`
            },
            data : {
                releases: releaseData
            }
        };
        try{
            const response = await axios.request(config);
            return response.data.releases;
        } catch (error) {
            this.logAxiosError(error);
            throw error;
        }
    },

    logAxiosError(error) {
        if (error.response) {
            // The request was made and the server responded with a status code that falls out of the range of 2xx
          //  console.error('Error response data:', error.response.data);
           // console.error('Error response status:', error.response.status);
        } else if (error.request) {
            // The request was made but no response was received
           // console.error('Error request:', error.request);
        } else {
            // Something happened in setting up the request that triggered an Error
            console.error('Error message:', error.message);
        }
    }
};

module.exports = apiCaller;