var defaultTemplates = {
  header: function header() {
    return '';
  },
  loader: function loader() {
    return '';
  },
  item: function item(_item) {
    return JSON.stringify(_item);
  }
};
export default defaultTemplates;