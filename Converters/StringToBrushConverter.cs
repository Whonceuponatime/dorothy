using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace Dorothy.Converters
{
    public class StringToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string hex && !string.IsNullOrEmpty(hex))
            {
                try { return new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)); }
                catch { }
            }
            return Brushes.Transparent;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
