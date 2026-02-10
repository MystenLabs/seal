var defaultTemplates = {
  text: function text() {
    return '';
  },
  button: function button(_ref) {
    var isRelevantSorted = _ref.isRelevantSorted;
    return isRelevantSorted ? 'See all results' : 'See relevant results';
  }
};
export default defaultTemplates;