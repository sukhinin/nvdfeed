export default {
  target: 'static',
  buildModules: [
    '@nuxtjs/vuetify'
  ],
  head: {
    titleTemplate: 'NVD Feed',
    meta: [
      { charset: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { hid: 'description', name: 'description', content: 'Recent CVE entries from NVD feed' }
    ]
  },
  build: {
    babel:{
      plugins: [
        ['@babel/plugin-proposal-class-properties', { loose: false }]
      ]
    }
  }
};
