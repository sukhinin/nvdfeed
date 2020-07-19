<template>
  <v-app>
    <v-app-bar app clipped-left color="amber">
      <v-app-bar-nav-icon @click="drawer=!drawer"></v-app-bar-nav-icon>
      <span class="title ml-3 mr-5">NVD&nbsp;<span class="font-weight-light">Feed</span></span>
    </v-app-bar>

    <v-navigation-drawer v-model="drawer" width="350" app clipped color="grey lighten-4">
      <v-container fluid class="px-5 py-4">
        <v-row dense>
          <v-col cols="12" class="text-body-2 text-uppercase">
            Last update
          </v-col>
          <v-col cols="12">
            <v-btn-toggle mandatory v-model="filter.updatedWithin" class="full-width">
              <v-btn small :value="24*60*60*1000">1 day</v-btn>
              <v-btn small :value="3*24*60*60*1000">3 days</v-btn>
              <v-btn small :value="7*24*60*60*1000">7 days</v-btn>
            </v-btn-toggle>
          </v-col>
          <v-col cols="12">
            <v-switch v-model="filter.includePreviouslyPublished"
                      label="Show updates of old CVEs"
                      class="my-0">
            </v-switch>
          </v-col>
        </v-row>
        <v-row dense>
          <v-col cols="12" class="text-body-2 text-uppercase">
            Severity
          </v-col>
          <v-col cols="12">
            <v-btn-toggle mandatory v-model="filter.severity" class="full-width">
              <v-btn small value="LOW">Low</v-btn>
              <v-btn small value="MEDIUM">Medium</v-btn>
              <v-btn small value="HIGH">High</v-btn>
              <v-btn small value="CRITICAL">Critical</v-btn>
            </v-btn-toggle>
          </v-col>
          <v-col cols="12">
            <v-switch v-model="filter.includeUnassignedSeverity"
                      label="Show without assigned severity"
                      class="my-0">
            </v-switch>
          </v-col>
        </v-row>
      </v-container>
    </v-navigation-drawer>

    <v-main>
      <v-container>
        <v-data-iterator :items="filteredItems"
                         :items-per-page="50"
                         :footer-props="{'items-per-page-options': [25, 50, 100]}"
                         v-on:pagination="onPagination">
          <template v-slot:default="props">
            <v-row>
              <v-col v-for="item in props.items" :key="item.id" cols="12">
                <v-card>
                  <v-card-title>
                    <a :href="'https://nvd.nist.gov/vuln/detail/' + item.id" target="_blank">{{ item.id }}</a>
                    <v-spacer></v-spacer>
                    <v-tooltip left v-if="item.vector" min-width="300">
                      <template v-slot:activator="{ on, attrs }">
                        <v-chip v-bind="attrs" v-on="on" :color="getSeverityColor(item.severity)">
                          {{ item.score || 'N/A' }} {{ item.severity }}
                        </v-chip>
                      </template>
                      <v-row no-gutters v-for="props in getDecodedVector(item.vector)" :key="props.label">
                        <v-col cols="7">{{props.label}}</v-col>
                        <v-col cols="5">{{props.value}}</v-col>
                      </v-row>
                    </v-tooltip>
                  </v-card-title>
                  <v-card-subtitle class="text-caption">
                      Published on {{ new Date(item.published).toLocaleDateString() }},
                      updated on {{ new Date(item.updated).toLocaleDateString() }}
                  </v-card-subtitle>
                  <v-card-text>
                    {{ item.description }}
                  </v-card-text>
                </v-card>
              </v-col>
            </v-row>
          </template>
        </v-data-iterator>
      </v-container>
    </v-main>
  </v-app>
</template>

<style>
  .full-width {
    width: 100%;
  }

  .full-width.v-item-group * {
    flex-grow: 1;
  }
</style>

<script>
  import feed from '~/static/nvdcve-mapped.json';

  const itemSeverityToMatchingFilterValuesMap = {
    'LOW': ['LOW'],
    'MEDIUM': ['LOW', 'MEDIUM'],
    'HIGH': ['LOW', 'MEDIUM', 'HIGH'],
    'CRITICAL': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
  };

  const itemSeverityToColorMap = {
    'CRITICAL': 'red lighten-2',
    'HIGH': 'orange lighten-2',
    'MEDIUM': 'amber lighten-2',
    'LOW': 'green lighten-2',
    'DEFAULT': 'grey lighten-2'
  };

  const cvssToPropertiesMap = {
    'AV': {
      label: 'Attack vector',
      values: { 'P': 'physical', 'L': 'local', 'A': 'adjacent network', 'N': 'network' }
    },
    'AC': {
      label: 'Attack complexity',
      values: { 'H': 'high', 'M': 'medium', 'L': 'low' }
    },
    'Au': {
      label: 'Authentication',
      values: { 'M': 'multiple', 'S': 'single', 'N': 'none' }
    },
    'PR': {
      label: 'Privileges required',
      values: { 'H': 'high', 'L': 'low', 'N': 'none' }
    },
    'UI': {
      label: 'User interaction',
      values: { 'N': 'none', 'R': 'required' }
    },
    'S': {
      label: 'Scope',
      values: { 'U': 'unchanged', 'C': 'changed' }
    },
    'C': {
      label: 'Confidentiality impact',
      values: { 'N': 'none', 'L': 'low', 'H': 'high', 'P': 'partial', 'C': 'complete' }
    },
    'I': {
      label: 'Integrity impact',
      values: { 'N': 'none', 'L': 'low', 'H': 'high', 'P': 'partial', 'C': 'complete' }
    },
    'A': {
      label: 'Availability impact',
      values: { 'N': 'none', 'L': 'low', 'H': 'high', 'P': 'partial', 'C': 'complete' }
    }
  };

  export default {
    data: function () {
      return {
        drawer: false,
        feed: feed,
        filter: {
          updatedWithin: 3 * 24 * 60 * 60 * 1000,
          includePreviouslyPublished: true,
          severity: 'HIGH',
          includeUnassignedSeverity: false
        }
      };
    },
    computed: {
      filteredItems: function () {
        const now = Date.now();
        const filterByTimestamp = (item) => {
          const timestamp = this.filter.includePreviouslyPublished ? item.updated : item.published;
          return now - timestamp < this.filter.updatedWithin;
        };

        const filterBySeverity = (item) => {
          const filterValues = itemSeverityToMatchingFilterValuesMap[item.severity];
          return filterValues ? filterValues.includes(this.filter.severity) : this.filter.includeUnassignedSeverity;
        };

        const filter = (item) => filterByTimestamp(item) && filterBySeverity(item);
        return this.feed.filter(filter);
      }
    },
    methods: {
      getSeverityColor: function (severity) {
        return itemSeverityToColorMap[severity] || itemSeverityToColorMap['DEFAULT'];
      },
      getDecodedVector: function (vector) {
        const mapCvssComponent = ([key, value]) => {
          const props = cvssToPropertiesMap[key];
          return props ? { label: props.label, value: props.values[value] } : { label: null, value: null };
        };
        return vector.split('/')
          .map(s => mapCvssComponent(s.split(':')))
          .filter(entry => entry.label && entry.value);
      },
      onPagination: function () {
        if (process.client) {
          window.requestAnimationFrame(() => this.$vuetify.goTo(0));
        }
      }
    }
  };
</script>
